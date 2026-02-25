import crypto from 'node:crypto';
import {
  REFERRAL_CODE_LENGTH,
  REFERRAL_MAX_CREDITS_PER_YEAR,
  REFERRAL_CREDIT_CHOICE_DEADLINE_DAYS,
  SubscriptionPlan,
  EARLY_BIRD_CAP,
} from '@meritum/shared/constants/platform.constants.js';
import { BusinessRuleError } from '../../lib/errors.js';
import {
  type ReferralCodeRepository,
  type ReferralRedemptionRepository,
} from './referral.repository.js';
import {
  type SubscriptionRepository,
  type PaymentRepository,
} from './platform.repository.js';

// ---------------------------------------------------------------------------
// Stripe interface (minimal, for invoice item creation)
// ---------------------------------------------------------------------------

export interface Stripe {
  invoiceItems: {
    create(params: {
      customer: string;
      amount: number;
      currency: string;
      description: string;
    }): Promise<{ id: string }>;
  };
}

// ---------------------------------------------------------------------------
// Dependency container
// ---------------------------------------------------------------------------

export type ReferralServiceDeps = {
  referralCodeRepo: ReferralCodeRepository;
  referralRedemptionRepo: ReferralRedemptionRepository;
  subscriptionRepo: SubscriptionRepository;
  paymentRepo: PaymentRepository;
  stripe: Stripe;
};

// ---------------------------------------------------------------------------
// Character set for referral codes (no 0/O/1/I/L)
// ---------------------------------------------------------------------------

const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

// ---------------------------------------------------------------------------
// D18-020: generateReferralCode
// ---------------------------------------------------------------------------

export async function generateReferralCode(
  deps: ReferralServiceDeps,
  userId: string,
): Promise<{ code: string; referralCodeId: string }> {
  // Check if user already has an active code
  const existing = await deps.referralCodeRepo.findReferralCodeByUserId(userId);
  if (existing) {
    return { code: existing.code, referralCodeId: existing.referralCodeId };
  }

  // Generate unique code with retry on collision
  const maxRetries = 10;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const bytes = crypto.randomBytes(REFERRAL_CODE_LENGTH);
    let code = '';
    for (let i = 0; i < REFERRAL_CODE_LENGTH; i++) {
      code += CODE_CHARS[bytes[i] % CODE_CHARS.length];
    }

    // Check for collision
    const collision = await deps.referralCodeRepo.findReferralCodeByCode(code);
    if (!collision) {
      const created = await deps.referralCodeRepo.createReferralCode(
        userId,
        code,
      );
      return { code: created.code, referralCodeId: created.referralCodeId };
    }
  }

  throw new BusinessRuleError(
    'Unable to generate unique referral code after maximum retries',
  );
}

// ---------------------------------------------------------------------------
// D18-021: redeemReferralCode
// ---------------------------------------------------------------------------

export async function redeemReferralCode(
  deps: ReferralServiceDeps,
  code: string,
  referredUserId: string,
): Promise<{ redemptionId: string }> {
  // 1. Validate code exists and is_active
  const referralCode = await deps.referralCodeRepo.findReferralCodeByCode(code);
  if (!referralCode || !referralCode.isActive) {
    throw new BusinessRuleError('Invalid or inactive referral code', {
      code: 'INVALID_REFERRAL_CODE',
    });
  }

  // 2. Validate referred user has NEVER had a subscription (any status)
  const existingSub =
    await deps.subscriptionRepo.findSubscriptionByProviderId(referredUserId);
  if (existingSub) {
    throw new BusinessRuleError('Referred user already has a subscription', {
      code: 'REFERRED_USER_HAS_SUBSCRIPTION',
    });
  }

  // 3. Validate referrer and referred not on same practice
  const referrerMembership =
    await deps.subscriptionRepo.getActivePracticeMembership(
      referralCode.referrerUserId,
    );
  const referredMembership =
    await deps.subscriptionRepo.getActivePracticeMembership(referredUserId);
  if (
    referrerMembership &&
    referredMembership &&
    referrerMembership.practiceId === referredMembership.practiceId
  ) {
    throw new BusinessRuleError(
      'Referrer and referred user are in the same practice',
      { code: 'SAME_PRACTICE' },
    );
  }

  // 4. Validate no existing PENDING redemption for referred user
  const existingPending =
    await deps.referralRedemptionRepo.findPendingByReferredUser(referredUserId);
  if (existingPending) {
    throw new BusinessRuleError(
      'Referred user already has a pending referral redemption',
      { code: 'PENDING_REDEMPTION_EXISTS' },
    );
  }

  // 5. Calculate anniversary year from referrer's subscription created_at
  const referrerSub =
    await deps.subscriptionRepo.findSubscriptionByProviderId(
      referralCode.referrerUserId,
    );
  let anniversaryYear = 1;
  if (referrerSub) {
    const subCreated = new Date(referrerSub.createdAt);
    const now = new Date();
    const diffMs = now.getTime() - subCreated.getTime();
    const diffYears = diffMs / (365.25 * 24 * 60 * 60 * 1000);
    anniversaryYear = Math.floor(diffYears) + 1;
  }

  // 6. Create PENDING redemption
  const redemption = await deps.referralRedemptionRepo.createRedemption({
    referralCodeId: referralCode.referralCodeId,
    referrerUserId: referralCode.referrerUserId,
    referredUserId,
    anniversaryYear,
  });

  return { redemptionId: redemption.redemptionId };
}

// ---------------------------------------------------------------------------
// D18-022: checkReferralQualification
// ---------------------------------------------------------------------------

function getCreditValue(plan: string): number {
  switch (plan) {
    case SubscriptionPlan.EARLY_BIRD_MONTHLY:
    case SubscriptionPlan.EARLY_BIRD_ANNUAL:
      return 199.0;
    case SubscriptionPlan.STANDARD_MONTHLY:
      return 279.0;
    case SubscriptionPlan.STANDARD_ANNUAL:
      return parseFloat((3181 / 12).toFixed(2));
    case SubscriptionPlan.CLINIC_MONTHLY:
      return 251.1;
    case SubscriptionPlan.CLINIC_ANNUAL:
      return parseFloat((2863 / 12).toFixed(2));
    default:
      return 279.0;
  }
}

function isClinicPlan(plan: string): boolean {
  return (
    plan === SubscriptionPlan.CLINIC_MONTHLY ||
    plan === SubscriptionPlan.CLINIC_ANNUAL
  );
}

export async function checkReferralQualification(
  deps: ReferralServiceDeps,
): Promise<{ qualified: number; expired: number; skipped: number }> {
  const result = { qualified: 0, expired: 0, skipped: 0 };

  // 1. Find all PENDING redemptions
  const pending = await deps.referralRedemptionRepo.findPendingRedemptions();

  for (const redemption of pending) {
    // 2. Check if referred user has a PAID payment_history record
    const referredSub =
      await deps.subscriptionRepo.findSubscriptionByProviderId(
        redemption.referredUserId,
      );
    if (!referredSub) {
      result.skipped++;
      continue;
    }

    const payments = await deps.paymentRepo.listPaymentsForSubscription(
      referredSub.subscriptionId,
      { page: 1, pageSize: 1000 },
    );

    const hasPaidPayment = payments.data.some(
      (p: any) => p.status === 'PAID',
    );
    if (!hasPaidPayment) {
      result.skipped++;
      continue;
    }

    // Get referrer's current subscription
    const referrerSub =
      await deps.subscriptionRepo.findSubscriptionByProviderId(
        redemption.referrerUserId,
      );

    // 5. If referrer has no active sub -> EXPIRED
    if (!referrerSub || referrerSub.status !== 'ACTIVE') {
      await deps.referralRedemptionRepo.updateRedemptionStatus(
        redemption.redemptionId,
        { status: 'EXPIRED' },
      );
      result.expired++;
      continue;
    }

    // 3. Calculate credit value
    const creditValue = getCreditValue(referrerSub.plan);

    // 4. Check 3-per-year cap
    const creditsUsed =
      await deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear(
        redemption.referrerUserId,
        redemption.anniversaryYear,
      );

    // 6. If cap reached -> EXPIRED
    if (creditsUsed >= REFERRAL_MAX_CREDITS_PER_YEAR) {
      await deps.referralRedemptionRepo.updateRedemptionStatus(
        redemption.redemptionId,
        { status: 'EXPIRED' },
      );
      result.expired++;
      continue;
    }

    // 7. If clinic plan -> QUALIFIED (wait for choice)
    if (isClinicPlan(referrerSub.plan)) {
      await deps.referralRedemptionRepo.updateRedemptionStatus(
        redemption.redemptionId,
        {
          status: 'QUALIFIED',
          creditMonthValueCad: creditValue.toFixed(2),
          qualifyingEventAt: new Date(),
        },
      );
      result.qualified++;
      continue;
    }

    // 8. If individual plan -> QUALIFIED then auto-apply
    await deps.referralRedemptionRepo.updateRedemptionStatus(
      redemption.redemptionId,
      {
        status: 'QUALIFIED',
        creditMonthValueCad: creditValue.toFixed(2),
        qualifyingEventAt: new Date(),
      },
    );

    // Auto-apply for individual plans
    await deps.stripe.invoiceItems.create({
      customer: referrerSub.stripeCustomerId,
      amount: -Math.round(creditValue * 100),
      currency: 'cad',
      description: `Referral credit: 1 month free (referral ${redemption.redemptionId})`,
    });

    await deps.referralRedemptionRepo.updateRedemptionStatus(
      redemption.redemptionId,
      {
        status: 'CREDITED',
        creditAppliedAt: new Date(),
      },
    );

    result.qualified++;
  }

  return result;
}

// ---------------------------------------------------------------------------
// D18-023: applyReferralCredit
// ---------------------------------------------------------------------------

export async function applyReferralCredit(
  deps: ReferralServiceDeps,
  redemptionId: string,
  userId: string,
  target?: string,
): Promise<void> {
  // 1. Load redemption, verify QUALIFIED status, verify userId matches referrer
  const redemption =
    await deps.referralRedemptionRepo.findRedemptionById(redemptionId);
  if (!redemption) {
    throw new BusinessRuleError('Redemption not found', {
      code: 'REDEMPTION_NOT_FOUND',
    });
  }
  if (redemption.status !== 'QUALIFIED') {
    throw new BusinessRuleError('Redemption is not in QUALIFIED status', {
      code: 'INVALID_REDEMPTION_STATUS',
    });
  }
  if (redemption.referrerUserId !== userId) {
    throw new BusinessRuleError('User does not own this redemption', {
      code: 'UNAUTHORIZED_REDEMPTION',
    });
  }

  const referrerSub =
    await deps.subscriptionRepo.findSubscriptionByProviderId(userId);
  if (!referrerSub) {
    throw new BusinessRuleError('Referrer has no subscription', {
      code: 'NO_SUBSCRIPTION',
    });
  }

  const creditValue = parseFloat(redemption.creditMonthValueCad ?? '0');

  // 2. For clinic plans: target is required
  if (isClinicPlan(referrerSub.plan)) {
    if (!target) {
      throw new BusinessRuleError(
        'Credit application target is required for clinic plans',
        { code: 'TARGET_REQUIRED' },
      );
    }

    // 3. PRACTICE_INVOICE: create negative Stripe invoice item on practice's customer
    if (target === 'PRACTICE_INVOICE') {
      await deps.stripe.invoiceItems.create({
        customer: referrerSub.stripeCustomerId,
        amount: -Math.round(creditValue * 100),
        currency: 'cad',
        description: `Referral credit: 1 month free (referral ${redemptionId})`,
      });
    }
    // 4. INDIVIDUAL_BANK: just store the target, no Stripe action

    // 6. Update status to CREDITED
    await deps.referralRedemptionRepo.updateRedemptionStatus(redemptionId, {
      status: 'CREDITED',
      creditAppliedTo: target,
      creditAppliedAt: new Date(),
    });
  } else {
    // 5. Individual plans: auto-apply via negative Stripe invoice item
    await deps.stripe.invoiceItems.create({
      customer: referrerSub.stripeCustomerId,
      amount: -Math.round(creditValue * 100),
      currency: 'cad',
      description: `Referral credit: 1 month free (referral ${redemptionId})`,
    });

    // 6. Update status to CREDITED
    await deps.referralRedemptionRepo.updateRedemptionStatus(redemptionId, {
      status: 'CREDITED',
      creditAppliedAt: new Date(),
    });
  }
}

// ---------------------------------------------------------------------------
// applyDefaultCreditChoice
// ---------------------------------------------------------------------------

export async function applyDefaultCreditChoice(
  deps: ReferralServiceDeps,
): Promise<number> {
  let appliedCount = 0;
  const deadlineCutoff = new Date(
    Date.now() - REFERRAL_CREDIT_CHOICE_DEADLINE_DAYS * 24 * 60 * 60 * 1000,
  );

  // Find all QUALIFIED redemptions
  const qualified =
    await deps.referralRedemptionRepo.findQualifiedRedemptions();

  for (const redemption of qualified) {
    // Only process redemptions older than the deadline
    const qualifiedAt = redemption.qualifyingEventAt ?? redemption.createdAt;
    if (new Date(qualifiedAt) > deadlineCutoff) {
      continue;
    }

    // Only apply to clinic plans
    const referrerSub =
      await deps.subscriptionRepo.findSubscriptionByProviderId(
        redemption.referrerUserId,
      );
    if (!referrerSub || !isClinicPlan(referrerSub.plan)) {
      continue;
    }

    // Auto-apply as PRACTICE_INVOICE
    const creditValue = parseFloat(redemption.creditMonthValueCad ?? '0');

    await deps.stripe.invoiceItems.create({
      customer: referrerSub.stripeCustomerId,
      amount: -Math.round(creditValue * 100),
      currency: 'cad',
      description: `Referral credit: 1 month free (referral ${redemption.redemptionId})`,
    });

    await deps.referralRedemptionRepo.updateRedemptionStatus(
      redemption.redemptionId,
      {
        status: 'CREDITED',
        creditAppliedTo: 'PRACTICE_INVOICE',
        creditAppliedAt: new Date(),
      },
    );

    appliedCount++;
  }

  return appliedCount;
}

// ---------------------------------------------------------------------------
// D18-024: shouldApplyRefereeIncentive
// ---------------------------------------------------------------------------

export async function shouldApplyRefereeIncentive(
  deps: ReferralServiceDeps,
  referredUserId: string,
  plan: string,
): Promise<boolean> {
  // Check if pending referral exists
  const pending =
    await deps.referralRedemptionRepo.findPendingByReferredUser(referredUserId);
  if (!pending) {
    return false;
  }

  // Check early bird window closed (>=100 EB subs)
  const ebCount = await deps.subscriptionRepo.countEarlyBirdSubscriptions();
  if (ebCount < EARLY_BIRD_CAP) {
    return false;
  }

  // Plan is not clinic or early bird
  if (
    plan === SubscriptionPlan.CLINIC_MONTHLY ||
    plan === SubscriptionPlan.CLINIC_ANNUAL ||
    plan === SubscriptionPlan.EARLY_BIRD_MONTHLY ||
    plan === SubscriptionPlan.EARLY_BIRD_ANNUAL
  ) {
    return false;
  }

  return true;
}
