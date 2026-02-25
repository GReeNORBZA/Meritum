// ============================================================================
// D19-002/003/004: Annual Cancellation & Stripe Refund Service
// ============================================================================

import {
  CancellationPolicy,
  determineCancellationPolicy,
  calculateAnnualRefund,
  SubscriptionPlanPricing,
  PaymentStatus,
  ANNUAL_CANCELLATION_FORFEIT_MESSAGE,
} from '@meritum/shared/constants/platform.constants.js';
import { SubscriptionStatus } from '@meritum/shared/constants/iam.constants.js';
import { BusinessRuleError, NotFoundError } from '../../lib/errors.js';
import {
  type SubscriptionRepository,
  type PaymentRepository,
} from './platform.repository.js';

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

export interface CancellationStripeClient {
  subscriptions: {
    update(
      subscriptionId: string,
      params: { cancel_at_period_end: boolean },
    ): Promise<{ id: string; status: string }>;
  };
  refunds: {
    create(params: {
      payment_intent: string;
      amount: number;
    }): Promise<{ id: string; amount: number; status: string }>;
  };
}

export interface CancellationServiceDeps {
  subscriptionRepo: SubscriptionRepository;
  paymentRepo: PaymentRepository;
  stripe: CancellationStripeClient;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface CancellationResult {
  policy: string;
  refundAmount: number | null;
  periodEnd: string;
  message: string;
}

export interface RefundRecord {
  refundId: string;
  paymentId: string;
  amount: number;
  status: string;
}

// ---------------------------------------------------------------------------
// D19-003: Stripe refund integration
// ---------------------------------------------------------------------------

/**
 * Issue a Stripe refund for an annual subscription.
 *
 * 1. Find the latest PAID payment for this subscription.
 * 2. Create Stripe refund with payment_intent and amount in cents.
 * 3. Record in payment_history with status REFUNDED and negative amounts.
 * 4. Return the refund record.
 */
export async function refundAnnualSubscription(
  deps: CancellationServiceDeps,
  subscriptionId: string,
  refundAmountCad: number,
): Promise<RefundRecord> {
  // 1. Find the latest PAID payment for this subscription
  const payments = await deps.paymentRepo.listPaymentsForSubscription(
    subscriptionId,
    { page: 1, pageSize: 50 },
  );

  const latestPaid = payments.data.find((p) => p.status === PaymentStatus.PAID);
  if (!latestPaid) {
    throw new BusinessRuleError('No paid payment found for refund', {
      code: 'NO_PAID_PAYMENT',
    });
  }

  // 2. Create Stripe refund (amount in cents)
  const refundCents = Math.round(refundAmountCad * 100);
  const paymentIntent =
    (latestPaid as any).stripePaymentIntentId ?? latestPaid.stripeInvoiceId;

  const stripeRefund = await deps.stripe.refunds.create({
    payment_intent: paymentIntent,
    amount: refundCents,
  });

  // 3. Record refund in payment_history with negative amounts
  const refundRecord = await deps.paymentRepo.recordPayment({
    subscriptionId,
    stripeInvoiceId: `refund_${stripeRefund.id}`,
    amountCad: (-refundAmountCad).toFixed(2),
    gstAmount: '0.00',
    totalCad: (-refundAmountCad).toFixed(2),
    status: PaymentStatus.REFUNDED,
    paidAt: new Date(),
  } as any);

  // 4. Return the refund record
  return {
    refundId: stripeRefund.id,
    paymentId: refundRecord.paymentId,
    amount: refundAmountCad,
    status: stripeRefund.status,
  };
}

// ---------------------------------------------------------------------------
// D19-002: handleCancellation
// ---------------------------------------------------------------------------

/**
 * Handle a physician-initiated cancellation.
 *
 * 1. Load user's subscription
 * 2. If no subscription or already cancelled -> throw BusinessRuleError
 * 3. Determine cancellation policy
 * 4. MONTHLY_CANCEL: cancel at period end via Stripe
 * 5. FORFEIT_PERIOD: cancel at period end, NO refund
 * 6. PRORATED_REFUND: calculate refund, issue Stripe refund, then cancel
 * 7. Update local subscription status to CANCELLED
 * 8. Return { policy, refundAmount, periodEnd, message }
 */
export async function handleCancellation(
  deps: CancellationServiceDeps,
  userId: string,
): Promise<CancellationResult> {
  // 1. Load user's subscription
  const subscription =
    await deps.subscriptionRepo.findSubscriptionByProviderId(userId);

  // 2. No subscription or already cancelled
  if (!subscription) {
    throw new BusinessRuleError('No active subscription found', {
      code: 'NO_SUBSCRIPTION',
    });
  }

  if (subscription.status === SubscriptionStatus.CANCELLED) {
    throw new BusinessRuleError('Subscription is already cancelled', {
      code: 'ALREADY_CANCELLED',
    });
  }

  // Calculate months elapsed since period start
  const periodStart = subscription.currentPeriodStart instanceof Date
    ? subscription.currentPeriodStart
    : new Date(subscription.currentPeriodStart);
  const now = new Date();
  const monthsElapsed = Math.floor(
    (now.getTime() - periodStart.getTime()) / (30 * 24 * 60 * 60 * 1000),
  );

  // 3. Determine cancellation policy
  const policy = determineCancellationPolicy(subscription.plan, monthsElapsed);

  const periodEnd = subscription.currentPeriodEnd instanceof Date
    ? subscription.currentPeriodEnd
    : new Date(subscription.currentPeriodEnd);
  const periodEndStr = periodEnd.toISOString();

  let refundAmount: number | null = null;
  let message: string;

  switch (policy) {
    // 4. MONTHLY_CANCEL: cancel at period end via Stripe
    case CancellationPolicy.MONTHLY_CANCEL: {
      await deps.stripe.subscriptions.update(
        subscription.stripeSubscriptionId,
        { cancel_at_period_end: true },
      );
      message = `Monthly subscription will be cancelled at period end (${periodEndStr}).`;
      break;
    }

    // 5. FORFEIT_PERIOD: cancel at period end, NO refund
    case CancellationPolicy.FORFEIT_PERIOD: {
      await deps.stripe.subscriptions.update(
        subscription.stripeSubscriptionId,
        { cancel_at_period_end: true },
      );
      message = ANNUAL_CANCELLATION_FORFEIT_MESSAGE.replace(
        '[period end date]',
        periodEndStr,
      );
      break;
    }

    // 6. PRORATED_REFUND: calculate refund, issue Stripe refund, then cancel
    case CancellationPolicy.PRORATED_REFUND: {
      // Look up the annual amount from the plan pricing
      const planPricing =
        SubscriptionPlanPricing[
          subscription.plan as keyof typeof SubscriptionPlanPricing
        ];
      const annualAmount = planPricing
        ? parseFloat(planPricing.amount)
        : 3181.0;

      const refundCalc = calculateAnnualRefund(annualAmount, monthsElapsed);

      if (refundCalc && refundCalc.refundAmount > 0) {
        // Issue Stripe refund
        await refundAnnualSubscription(
          deps,
          subscription.subscriptionId,
          refundCalc.refundAmount,
        );
        refundAmount = refundCalc.refundAmount;
        message = `Annual subscription cancelled. Refund of $${refundCalc.refundAmount.toFixed(2)} CAD for ${refundCalc.monthsRemaining} remaining month(s).`;
      } else {
        refundAmount = 0;
        message = `Annual subscription cancelled. No refund — subscription has been fully used.`;
      }

      await deps.stripe.subscriptions.update(
        subscription.stripeSubscriptionId,
        { cancel_at_period_end: true },
      );
      break;
    }

    default: {
      throw new BusinessRuleError('Unknown cancellation policy');
    }
  }

  // 7. Update local subscription status to CANCELLED
  await deps.subscriptionRepo.updateSubscriptionStatus(
    subscription.subscriptionId,
    SubscriptionStatus.CANCELLED,
    { cancelled_at: new Date() },
  );

  // 8. Return result
  return {
    policy,
    refundAmount,
    periodEnd: periodEndStr,
    message,
  };
}
