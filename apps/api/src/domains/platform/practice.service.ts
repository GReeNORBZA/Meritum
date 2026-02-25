import crypto from 'node:crypto';
import {
  BillingMode,
  CLINIC_MINIMUM_PHYSICIANS,
  GST_RATE,
  PracticeInvitationStatus,
  PracticeStatus,
  PRACTICE_INVITATION_EXPIRY_DAYS,
  SubscriptionPlan,
  SubscriptionPlanPricing,
} from '@meritum/shared/constants/platform.constants.js';
import { Role } from '@meritum/shared/constants/iam.constants.js';
import { BusinessRuleError, ForbiddenError, NotFoundError } from '../../lib/errors.js';
import { type PracticeRepository } from './practice.repository.js';
import { type PracticeMembershipRepository } from './practice-membership.repository.js';
import { type PracticeInvitationRepository } from './practice-invitation.repository.js';
import {
  type SelectPractice,
  type SelectPracticeInvitation,
  type SelectPracticeMembership,
} from '@meritum/shared/schemas/db/platform.schema.js';

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

export interface PracticeUserRepo {
  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    fullName: string;
    role: string;
  } | undefined>;
  findUserByEmail(email: string): Promise<{
    userId: string;
    email: string;
    fullName: string;
    role: string;
  } | undefined>;
  updateUserRole(userId: string, role: string): Promise<void>;
}

export interface PracticeSubscriptionRepo {
  findActiveEarlyBirdByProviderId(providerId: string): Promise<{
    plan: string;
    status: string;
    earlyBirdLockedUntil?: Date | null;
  } | null>;
  findActiveSubscriptionByProviderId?(providerId: string): Promise<{
    subscriptionId: string;
    stripeSubscriptionId: string;
    plan: string;
    status: string;
  } | null>;
  createSubscription?(data: {
    providerId: string;
    stripeCustomerId: string;
    stripeSubscriptionId: string;
    plan: string;
    status: string;
    currentPeriodStart: Date;
    currentPeriodEnd: Date;
  }): Promise<{ subscriptionId: string }>;
}

export interface PracticeStripeClient {
  customers: {
    create(params: {
      name: string;
      email: string;
      metadata?: Record<string, string>;
    }): Promise<{ id: string }>;
  };
  subscriptions?: {
    cancel(subscriptionId: string): Promise<{ id: string; status: string }>;
    update(subscriptionId: string, params: {
      quantity: number;
      proration_behavior: string;
    }): Promise<{ id: string; quantity: number }>;
    create?(params: {
      customer: string;
      items: Array<{ price: string; quantity: number }>;
      metadata?: Record<string, string>;
    }): Promise<{ id: string; status: string }>;
  };
}

export interface PracticeAuditLogger {
  log(entry: {
    action: string;
    resourceType: string;
    resourceId: string;
    actorType: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}

export interface PracticeNotifier {
  sendInvitationEmail(params: {
    toEmail: string;
    practiceName: string;
    inviterName: string;
    acceptUrl: string;
  }): Promise<void>;
  sendRemovalNotification?(params: {
    toEmail: string;
    practiceName: string;
    effectiveDate: string;
  }): Promise<void>;
  sendHeadcountWarning?(params: {
    toEmail: string;
    practiceName: string;
    projectedHeadcount: number;
  }): Promise<void>;
  sendDissolutionNotification?(params: {
    toEmail: string;
    practiceName: string;
    billingMode: string;
    newPlan?: string;
  }): Promise<void>;
}

export interface PracticeServiceDeps {
  practiceRepo: PracticeRepository;
  membershipRepo: PracticeMembershipRepository;
  invitationRepo: PracticeInvitationRepository;
  userRepo: PracticeUserRepo;
  subscriptionRepo: PracticeSubscriptionRepo;
  stripe: PracticeStripeClient;
  notifier?: PracticeNotifier;
  auditLogger?: PracticeAuditLogger;
}

// ---------------------------------------------------------------------------
// Helper: compute period end
// ---------------------------------------------------------------------------

function computePeriodEnd(
  start: Date,
  billingFrequency: 'MONTHLY' | 'ANNUAL',
): Date {
  const end = new Date(start);
  if (billingFrequency === 'ANNUAL') {
    end.setFullYear(end.getFullYear() + 1);
  } else {
    end.setMonth(end.getMonth() + 1);
  }
  return end;
}

// ---------------------------------------------------------------------------
// Helper: determine billing mode for admin
// ---------------------------------------------------------------------------

function isEarlyBirdPlan(plan: string): boolean {
  return (
    plan === SubscriptionPlan.EARLY_BIRD_MONTHLY ||
    plan === SubscriptionPlan.EARLY_BIRD_ANNUAL
  );
}

// ---------------------------------------------------------------------------
// Service: Create Practice
// ---------------------------------------------------------------------------

/**
 * Create a new practice, admin membership, assign PRACTICE_ADMIN role,
 * and create a Stripe customer.
 *
 * Steps 4-7 are wrapped in a logical transaction:
 * if Stripe customer creation fails, the practice is rolled back via
 * the caller providing a transactional DB connection.
 *
 * 1. Validate the admin user exists and is a physician.
 * 2. Check the user does not already admin a practice.
 * 3. Check the user is not already a member of another practice.
 * 4. Create the practice record.
 * 5. Create a practice membership for the admin.
 * 6. Assign PRACTICE_ADMIN role to the user.
 * 7. Create a Stripe customer for the practice.
 * 8. Audit log the practice creation.
 * 9. Return the created practice record.
 */
export async function createPractice(
  deps: PracticeServiceDeps,
  adminUserId: string,
  name: string,
  billingFrequency: 'MONTHLY' | 'ANNUAL',
): Promise<SelectPractice> {
  // 1. Validate the admin user exists and is a physician
  const user = await deps.userRepo.findUserById(adminUserId);
  if (!user) {
    throw new NotFoundError('User');
  }
  if (user.role !== Role.PHYSICIAN) {
    throw new BusinessRuleError(
      'Only physicians can create a practice',
      { code: 'NOT_A_PHYSICIAN' },
    );
  }

  // 2. Check the user does not already admin a practice
  const existingPractice = await deps.practiceRepo.findPracticeByAdminUserId(adminUserId);
  if (existingPractice) {
    throw new BusinessRuleError(
      'User already administers a practice',
      { code: 'ALREADY_PRACTICE_ADMIN' },
    );
  }

  // 3. Check the user is not already a member of another practice
  const existingMembership = await deps.membershipRepo.findActiveMembershipByPhysicianId(adminUserId);
  if (existingMembership) {
    throw new BusinessRuleError(
      'User is already a member of a practice',
      { code: 'ALREADY_ON_PRACTICE' },
    );
  }

  // 4. Create the practice record
  const now = new Date();
  const currentPeriodEnd = computePeriodEnd(now, billingFrequency);

  const practice = await deps.practiceRepo.createPractice({
    name,
    adminUserId,
    billingFrequency,
    status: PracticeStatus.ACTIVE,
    currentPeriodStart: now,
    currentPeriodEnd,
  } as any);

  // 5. Create a practice membership for the admin
  // Determine billing mode based on admin's current subscription
  // D17-013: Check earlyBirdLockedUntil — expired early bird is treated as non-early-bird
  let billingMode: string = BillingMode.PRACTICE_CONSOLIDATED;
  const activeSubscription = await deps.subscriptionRepo.findActiveEarlyBirdByProviderId(adminUserId);
  if (activeSubscription && isEarlyBirdPlan(activeSubscription.plan)) {
    // If earlyBirdLockedUntil is set, it must be in the future; if not set, active early bird counts
    const lockValid = !activeSubscription.earlyBirdLockedUntil ||
      activeSubscription.earlyBirdLockedUntil > new Date();
    if (lockValid) {
      billingMode = BillingMode.INDIVIDUAL_EARLY_BIRD;
    }
  }

  await deps.membershipRepo.createMembership({
    practiceId: practice.practiceId,
    physicianUserId: adminUserId,
    billingMode,
    joinedAt: now,
  } as any);

  // 6. Assign PRACTICE_ADMIN role to the user (role stacking: retains PHYSICIAN permissions)
  await deps.userRepo.updateUserRole(adminUserId, Role.PRACTICE_ADMIN);

  // 7. Create a Stripe customer for the practice — NO PHI sent
  let stripeCustomer: { id: string };
  try {
    stripeCustomer = await deps.stripe.customers.create({
      name,
      email: user.email,
      metadata: { practice_id: practice.practiceId },
    });
  } catch (error) {
    // Stripe failure — propagate to trigger rollback in transactional context
    throw error;
  }

  // Update the practice record with the Stripe customer ID
  const updatedPractice = await deps.practiceRepo.updatePractice(
    practice.practiceId,
    { stripeCustomerId: stripeCustomer.id } as any,
  );

  // 8. Audit log the practice creation
  await deps.auditLogger?.log({
    action: 'practice.created',
    resourceType: 'practice',
    resourceId: practice.practiceId,
    actorType: 'physician',
    metadata: {
      adminUserId,
      practiceName: name,
    },
  });

  // 9. Return the created practice record
  return updatedPractice;
}

// ---------------------------------------------------------------------------
// Service: Invite Physician to Practice
// ---------------------------------------------------------------------------

/**
 * Invite a physician to join a practice by email.
 *
 * 1. Validate the inviter is PRACTICE_ADMIN for this practice.
 * 2. Validate the practice is ACTIVE.
 * 3. Normalize the email.
 * 4. Check if user already on this practice.
 * 5. Check if user already on another active practice.
 * 6. Check for existing pending invitation.
 * 7. Generate invitation token (raw + hash).
 * 8. Create the invitation record (stores hash only).
 * 9. Emit notification email with raw token.
 * 10. Audit log.
 * 11. Return the invitation record (without raw token).
 */
export async function invitePhysician(
  deps: PracticeServiceDeps,
  practiceId: string,
  email: string,
  invitedByUserId: string,
): Promise<SelectPracticeInvitation> {
  // 1. Validate the inviter is PRACTICE_ADMIN for this practice
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new NotFoundError('Practice');
  }
  if (practice.adminUserId !== invitedByUserId) {
    throw new ForbiddenError('Not a practice admin');
  }

  // 2. Validate the practice is ACTIVE
  if (practice.status !== PracticeStatus.ACTIVE) {
    throw new BusinessRuleError(
      'Practice is not active',
      { code: 'PRACTICE_NOT_ACTIVE' },
    );
  }

  // 3. Normalize the email
  const normalizedEmail = email.toLowerCase().trim();

  // 4. Check if user already on this practice
  const existingUser = await deps.userRepo.findUserByEmail(normalizedEmail);
  if (existingUser) {
    const existingMembership = await deps.membershipRepo.findMembershipByPracticeAndPhysician(
      practiceId,
      existingUser.userId,
    );
    if (existingMembership) {
      throw new BusinessRuleError(
        'User is already a member of this practice',
        { code: 'ALREADY_ON_PRACTICE' },
      );
    }

    // 5. Check if user already on another active practice
    const otherMembership = await deps.membershipRepo.findActiveMembershipByPhysicianId(
      existingUser.userId,
    );
    if (otherMembership && otherMembership.practiceId !== practiceId) {
      throw new BusinessRuleError(
        'User is already a member of another practice',
        { code: 'ON_ANOTHER_PRACTICE' },
      );
    }
  }

  // 6. Check for existing pending invitation
  const pendingInvitation = await deps.invitationRepo.findPendingInvitationByEmail(
    normalizedEmail,
    practiceId,
  );
  if (pendingInvitation) {
    throw new BusinessRuleError(
      'An invitation is already pending for this email',
      { code: 'INVITATION_ALREADY_PENDING' },
    );
  }

  // 7. Generate invitation token
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  // 8. Create the invitation record
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + PRACTICE_INVITATION_EXPIRY_DAYS);

  const invitation = await deps.invitationRepo.createInvitation({
    practiceId,
    invitedEmail: normalizedEmail,
    invitedByUserId,
    status: 'PENDING',
    tokenHash,
    expiresAt,
  });

  // 9. Emit notification email with raw token — NO PHI in email
  const inviter = await deps.userRepo.findUserById(invitedByUserId);
  const acceptUrl = `https://meritum.ca/practice/invite/accept?token=${rawToken}`;

  await deps.notifier?.sendInvitationEmail({
    toEmail: normalizedEmail,
    practiceName: practice.name,
    inviterName: inviter?.fullName ?? 'A practice administrator',
    acceptUrl,
  });

  // 10. Audit log
  await deps.auditLogger?.log({
    action: 'practice.invitation_sent',
    resourceType: 'practice_invitation',
    resourceId: invitation.invitationId,
    actorType: 'physician',
    metadata: {
      practiceId,
      invitedEmail: normalizedEmail,
      invitedByUserId,
    },
  });

  // 11. Return the invitation record (raw token NOT included — sent via email only)
  return invitation;
}

// ---------------------------------------------------------------------------
// Service: Accept Practice Invitation
// ---------------------------------------------------------------------------

/**
 * Accept a practice invitation using a raw token.
 *
 * 1. Hash the incoming token and find the invitation.
 * 2. Validate: PENDING status, not expired, email matches accepting user.
 * 3. Validate: physician is not already on another practice.
 * 4. Determine billing_mode based on physician's current subscription.
 * 5. Create the membership record.
 * 6. Update invitation status to ACCEPTED.
 * 7. Handle Stripe subscription transition (cancel individual / increment practice).
 * 8. Audit log and return membership.
 */
export async function acceptInvitation(
  deps: PracticeServiceDeps,
  token: string,
  acceptingUserId: string,
): Promise<SelectPracticeMembership> {
  // 1. Hash the incoming token
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  // 2. Find the invitation by token hash
  const invitation = await deps.invitationRepo.findInvitationByTokenHash(tokenHash);
  if (!invitation) {
    throw new NotFoundError('Invitation');
  }

  // 3. Validate the invitation is PENDING
  if (invitation.status !== PracticeInvitationStatus.PENDING) {
    throw new BusinessRuleError(
      'Invitation is not pending',
      { code: 'INVITATION_NOT_PENDING' },
    );
  }

  // 4. Validate not expired
  const now = new Date();
  if (invitation.expiresAt < now) {
    // Update status to EXPIRED before throwing
    await deps.invitationRepo.updateInvitationStatus(
      invitation.invitationId,
      PracticeInvitationStatus.EXPIRED,
    );
    throw new BusinessRuleError(
      'Invitation has expired',
      { code: 'INVITATION_EXPIRED' },
    );
  }

  // 5. Validate the accepting user's email matches the invitation
  const user = await deps.userRepo.findUserById(acceptingUserId);
  if (!user) {
    throw new NotFoundError('User');
  }
  if (user.email.toLowerCase() !== invitation.invitedEmail.toLowerCase()) {
    throw new ForbiddenError('Email does not match invitation');
  }

  // 6. Validate the physician is not already on another practice
  const existingMembership = await deps.membershipRepo.findActiveMembershipByPhysicianId(
    acceptingUserId,
  );
  if (existingMembership) {
    throw new BusinessRuleError(
      'Physician is already a member of a practice',
      { code: 'ALREADY_ON_PRACTICE' },
    );
  }

  // 7. Determine billing_mode (CRITICAL — checked at acceptance time)
  // D17-013: Check earlyBirdLockedUntil — expired early bird is treated as non-early-bird
  let billingMode: string = BillingMode.PRACTICE_CONSOLIDATED;
  const activeEarlyBird = await deps.subscriptionRepo.findActiveEarlyBirdByProviderId(
    acceptingUserId,
  );
  if (activeEarlyBird && isEarlyBirdPlan(activeEarlyBird.plan)) {
    // If earlyBirdLockedUntil is set, it must be in the future; if not set, active early bird counts
    const lockValid = !activeEarlyBird.earlyBirdLockedUntil ||
      activeEarlyBird.earlyBirdLockedUntil > new Date();
    if (lockValid) {
      billingMode = BillingMode.INDIVIDUAL_EARLY_BIRD;
    }
  }

  // 8. Create the membership
  const membership = await deps.membershipRepo.createMembership({
    practiceId: invitation.practiceId,
    physicianUserId: acceptingUserId,
    billingMode,
    joinedAt: now,
  } as any);

  // 9. Update invitation status to ACCEPTED
  await deps.invitationRepo.updateInvitationStatus(
    invitation.invitationId,
    PracticeInvitationStatus.ACCEPTED,
  );

  // 10. Handle Stripe subscription transition
  if (billingMode === BillingMode.PRACTICE_CONSOLIDATED) {
    // Cancel the physician's individual subscription (if any)
    const individualSub = await deps.subscriptionRepo.findActiveSubscriptionByProviderId?.(
      acceptingUserId,
    );
    if (individualSub && deps.stripe.subscriptions) {
      await deps.stripe.subscriptions.cancel(individualSub.stripeSubscriptionId);
    }

    // Increment the practice's Stripe subscription quantity
    const practice = await deps.practiceRepo.findPracticeById(invitation.practiceId);
    if (practice?.stripeSubscriptionId && deps.stripe.subscriptions) {
      const consolidatedCount = await deps.practiceRepo.getConsolidatedSeatCount(
        invitation.practiceId,
      );
      await deps.stripe.subscriptions.update(practice.stripeSubscriptionId, {
        quantity: consolidatedCount,
        proration_behavior: 'create_prorations',
      });
    }
  }
  // If INDIVIDUAL_EARLY_BIRD: no Stripe changes — physician keeps their existing subscription

  // 11. Audit log
  await deps.auditLogger?.log({
    action: 'practice.invitation_accepted',
    resourceType: 'practice_membership',
    resourceId: membership.membershipId,
    actorType: 'physician',
    metadata: {
      practiceId: invitation.practiceId,
      physicianUserId: acceptingUserId,
      billingMode,
      invitationId: invitation.invitationId,
    },
  });

  // 12. Return the created membership record
  return membership;
}

// ---------------------------------------------------------------------------
// Helper: compute end of current calendar month (UTC)
// ---------------------------------------------------------------------------

function endOfCurrentMonth(now: Date): Date {
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  // Day 0 of next month = last day of current month
  const lastDay = new Date(Date.UTC(year, month + 1, 0, 23, 59, 59, 999));
  return lastDay;
}

// ---------------------------------------------------------------------------
// Service: Remove Physician from Practice
// ---------------------------------------------------------------------------

/**
 * Schedule a physician for removal from a practice at end of current month.
 *
 * 1. Validate the remover is PRACTICE_ADMIN for this practice.
 * 2. Cannot remove the admin themselves.
 * 3. Find the active membership.
 * 4. Check if removal is already scheduled.
 * 5. Calculate removal effective date (end of current calendar month).
 * 6. Schedule the removal (set removed_at + removal_effective_at).
 * 7. Check headcount — warn if practice drops below minimum.
 * 8. Emit notification to the removed physician.
 * 9. Audit log.
 */
export async function removePhysician(
  deps: PracticeServiceDeps,
  practiceId: string,
  physicianUserId: string,
  removedByUserId: string,
): Promise<void> {
  // 1. Validate the remover is PRACTICE_ADMIN for this practice
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new NotFoundError('Practice');
  }
  if (practice.adminUserId !== removedByUserId) {
    throw new ForbiddenError('Not a practice admin');
  }

  // 2. Cannot remove the admin themselves
  if (physicianUserId === practice.adminUserId) {
    throw new BusinessRuleError(
      'Cannot remove the practice admin',
      { code: 'CANNOT_REMOVE_ADMIN' },
    );
  }

  // 3. Find the active membership
  const membership = await deps.membershipRepo.findMembershipByPracticeAndPhysician(
    practiceId,
    physicianUserId,
  );
  if (!membership) {
    throw new NotFoundError('Membership');
  }

  // 4. Check if removal is already scheduled
  if (membership.removalEffectiveAt) {
    throw new BusinessRuleError(
      'Removal is already scheduled for this physician',
      { code: 'REMOVAL_ALREADY_SCHEDULED' },
    );
  }

  // 5. Calculate removal effective date — end of current calendar month
  const now = new Date();
  const removalEffectiveAt = endOfCurrentMonth(now);

  // 6. Schedule the removal — do NOT set is_active = false
  await deps.membershipRepo.setRemovalScheduled(
    membership.membershipId,
    now,
    removalEffectiveAt,
  );

  // 7. Check headcount after this removal takes effect
  const currentHeadcount = await deps.practiceRepo.getActiveHeadcount(practiceId);
  const projectedHeadcount = currentHeadcount - 1;

  if (projectedHeadcount < CLINIC_MINIMUM_PHYSICIANS) {
    // Find admin user for notification
    const adminUser = await deps.userRepo.findUserById(practice.adminUserId);
    if (adminUser) {
      await deps.notifier?.sendHeadcountWarning?.({
        toEmail: adminUser.email,
        practiceName: practice.name,
        projectedHeadcount,
      });
    }

    // Log warning in audit
    await deps.auditLogger?.log({
      action: 'practice.headcount_warning',
      resourceType: 'practice',
      resourceId: practiceId,
      actorType: 'system',
      metadata: {
        currentHeadcount,
        projectedHeadcount,
        minimumRequired: CLINIC_MINIMUM_PHYSICIANS,
      },
    });
  }

  // 8. Emit notification to the removed physician
  const removedUser = await deps.userRepo.findUserById(physicianUserId);
  if (removedUser) {
    await deps.notifier?.sendRemovalNotification?.({
      toEmail: removedUser.email,
      practiceName: practice.name,
      effectiveDate: removalEffectiveAt.toISOString(),
    });
  }

  // 9. Audit log the removal
  await deps.auditLogger?.log({
    action: 'practice.physician_removed',
    resourceType: 'practice_membership',
    resourceId: membership.membershipId,
    actorType: 'physician',
    metadata: {
      practiceId,
      physicianUserId,
      removedByUserId,
      removalEffectiveAt: removalEffectiveAt.toISOString(),
    },
  });
}

// ---------------------------------------------------------------------------
// Helper: map practice billing frequency to individual standard plan
// ---------------------------------------------------------------------------

function getStandardPlanForFrequency(
  billingFrequency: string,
): string {
  return billingFrequency === 'ANNUAL'
    ? SubscriptionPlan.STANDARD_ANNUAL
    : SubscriptionPlan.STANDARD_MONTHLY;
}

// ---------------------------------------------------------------------------
// Service: Handle End-of-Month Removals (scheduled job)
// ---------------------------------------------------------------------------

/**
 * Process pending removals that have reached their effective date.
 *
 * Runs at end of each calendar month (or daily, checking for pending removals).
 *
 * 1. Find all memberships where removal_effective_at <= now AND is_active = true.
 * 2. Group by practice_id.
 * 3. For each practice:
 *    a. Deactivate each pending removal membership.
 *    b. Decrement Stripe quantity for PRACTICE_CONSOLIDATED removals.
 *    c. Check remaining headcount.
 *    d. If headcount < CLINIC_MINIMUM_PHYSICIANS (5), dissolve the practice.
 * 4. Return summary.
 */
export async function handleEndOfMonthRemovals(
  deps: PracticeServiceDeps,
): Promise<{ processedCount: number; dissolvedPractices: string[] }> {
  const now = new Date();
  let processedCount = 0;
  const dissolvedPractices: string[] = [];

  // 1. Find all pending removals
  const pendingRemovals = await deps.membershipRepo.findPendingRemovals(now);

  if (pendingRemovals.length === 0) {
    return { processedCount: 0, dissolvedPractices: [] };
  }

  // 2. Group by practice_id
  const byPractice = new Map<string, typeof pendingRemovals>();
  for (const membership of pendingRemovals) {
    const existing = byPractice.get(membership.practiceId) ?? [];
    existing.push(membership);
    byPractice.set(membership.practiceId, existing);
  }

  // 3. Process each practice
  for (const [practiceId, removals] of byPractice) {
    const practice = await deps.practiceRepo.findPracticeById(practiceId);
    if (!practice) continue;

    // 3a. Process each removal
    for (const membership of removals) {
      await deps.membershipRepo.deactivateMembership(membership.membershipId);
      processedCount++;

      // Decrement Stripe quantity for PRACTICE_CONSOLIDATED only
      if (
        membership.billingMode === BillingMode.PRACTICE_CONSOLIDATED &&
        practice.stripeSubscriptionId &&
        deps.stripe.subscriptions
      ) {
        const newSeatCount = await deps.practiceRepo.getConsolidatedSeatCount(practiceId);
        await deps.stripe.subscriptions.update(practice.stripeSubscriptionId, {
          quantity: newSeatCount,
          proration_behavior: 'create_prorations',
        });
      }
      // INDIVIDUAL_EARLY_BIRD: no Stripe quantity change
    }

    // 3b. Check remaining headcount after all removals for this practice
    const headcount = await deps.practiceRepo.getActiveHeadcount(practiceId);

    // 3c. Dissolve if below minimum
    if (headcount < CLINIC_MINIMUM_PHYSICIANS) {
      await dissolvePractice(deps, practice, headcount);
      dissolvedPractices.push(practiceId);
    }
  }

  return { processedCount, dissolvedPractices };
}

// ---------------------------------------------------------------------------
// Helper: Dissolve a practice when headcount drops below minimum
// ---------------------------------------------------------------------------

async function dissolvePractice(
  deps: PracticeServiceDeps,
  practice: SelectPractice,
  remainingHeadcount: number,
): Promise<void> {
  const practiceId = practice.practiceId;

  // i. Cancel practice Stripe subscription
  if (practice.stripeSubscriptionId && deps.stripe.subscriptions) {
    await deps.stripe.subscriptions.cancel(practice.stripeSubscriptionId);
  }

  // ii. Transition PRACTICE_CONSOLIDATED members to individual subscriptions
  const consolidatedMembers = await deps.membershipRepo.findMembershipsByBillingMode(
    practiceId,
    BillingMode.PRACTICE_CONSOLIDATED,
  );

  const individualPlan = getStandardPlanForFrequency(practice.billingFrequency);

  for (const member of consolidatedMembers) {
    const user = await deps.userRepo.findUserById(member.physicianUserId);
    if (!user) continue;

    // Create a new individual Stripe subscription
    if (
      deps.stripe.subscriptions?.create &&
      deps.subscriptionRepo.createSubscription
    ) {
      const stripeCustomer = await deps.stripe.customers.create({
        name: user.fullName,
        email: user.email,
        metadata: { meritum_user_id: member.physicianUserId },
      });

      const stripeSub = await deps.stripe.subscriptions.create({
        customer: stripeCustomer.id,
        items: [{ price: individualPlan, quantity: 1 }],
        metadata: {
          meritum_user_id: member.physicianUserId,
          source: 'practice_dissolution',
        },
      });

      const periodEnd = computePeriodEnd(
        new Date(),
        practice.billingFrequency as 'MONTHLY' | 'ANNUAL',
      );

      await deps.subscriptionRepo.createSubscription({
        providerId: member.physicianUserId,
        stripeCustomerId: stripeCustomer.id,
        stripeSubscriptionId: stripeSub.id,
        plan: individualPlan,
        status: 'ACTIVE',
        currentPeriodStart: new Date(),
        currentPeriodEnd: periodEnd,
      });
    }

    // Notify PRACTICE_CONSOLIDATED member
    await deps.notifier?.sendDissolutionNotification?.({
      toEmail: user.email,
      practiceName: practice.name,
      billingMode: BillingMode.PRACTICE_CONSOLIDATED,
      newPlan: individualPlan,
    });
  }

  // iii. INDIVIDUAL_EARLY_BIRD members keep their subscriptions — just notify
  const earlyBirdMembers = await deps.membershipRepo.findMembershipsByBillingMode(
    practiceId,
    BillingMode.INDIVIDUAL_EARLY_BIRD,
  );

  for (const member of earlyBirdMembers) {
    const user = await deps.userRepo.findUserById(member.physicianUserId);
    if (!user) continue;

    await deps.notifier?.sendDissolutionNotification?.({
      toEmail: user.email,
      practiceName: practice.name,
      billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
    });
  }

  // Notify admin
  const adminUser = await deps.userRepo.findUserById(practice.adminUserId);
  if (adminUser) {
    await deps.notifier?.sendDissolutionNotification?.({
      toEmail: adminUser.email,
      practiceName: practice.name,
      billingMode: 'ADMIN',
    });
  }

  // iv. Deactivate all remaining memberships
  await deps.membershipRepo.deactivateAllMemberships(practiceId);

  // v. Update practice status to CANCELLED
  await deps.practiceRepo.updatePracticeStatus(practiceId, PracticeStatus.CANCELLED);

  // vi. Audit log
  await deps.auditLogger?.log({
    action: 'practice.dissolved',
    resourceType: 'practice',
    resourceId: practiceId,
    actorType: 'system',
    metadata: {
      remainingMemberCount: remainingHeadcount,
      reason: 'BELOW_MINIMUM_HEADCOUNT',
      minimumRequired: CLINIC_MINIMUM_PHYSICIANS,
    },
  });
}

// ---------------------------------------------------------------------------
// Return types for practice seat and invoice queries
// ---------------------------------------------------------------------------

/**
 * ZERO PHI seat record. Contains ONLY practice account management data.
 * Per Pricing Gap Closure Spec B1-11: no claim data, billing volumes,
 * rejection rates, patient data, analytics, AI suggestions, or individual
 * payment history may appear here.
 */
export interface PracticeSeat {
  physicianName: string;
  email: string;
  joinedAt: Date;
  billingMode: string;
}

export interface PracticeInvoiceInfo {
  totalAmount: string;
  perSeatRate: string;
  consolidatedSeatCount: number;
  totalHeadcount: number;
  billingFrequency: string;
  nextInvoiceDate: Date;
  gstAmount: string;
}

// ---------------------------------------------------------------------------
// Service: Get Practice Seats — ZERO PHI
// ---------------------------------------------------------------------------

/**
 * Returns the list of active practice members with ONLY:
 * physicianName, email, joinedAt, billingMode.
 *
 * SECURITY: The repository query joins ONLY practice_memberships with users.
 * It NEVER joins with claims, patients, analytics_cache, generated_reports,
 * ai_suggestion_events, payment_history, or any other PHI-containing table.
 *
 * This is enforced at the repository layer via the userRepo.findUserById
 * call which returns only { userId, email, fullName, role }.
 */
export async function getPracticeSeats(
  deps: PracticeServiceDeps,
  practiceId: string,
  adminUserId: string,
): Promise<PracticeSeat[]> {
  // 1. Validate caller is PRACTICE_ADMIN for this practice
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new NotFoundError('Practice');
  }
  if (practice.adminUserId !== adminUserId) {
    throw new ForbiddenError('Not a practice admin');
  }

  // 2. Get active memberships — ONLY from practice_memberships table
  const memberships = await deps.membershipRepo.findActiveMembershipsByPracticeId(practiceId);

  // 3. For each membership, get user details (name + email ONLY)
  const seats: PracticeSeat[] = [];
  for (const membership of memberships) {
    const user = await deps.userRepo.findUserById(membership.physicianUserId);
    if (!user) continue;

    // 4. Map to PracticeSeat — ONLY these four fields, nothing else
    seats.push({
      physicianName: user.fullName,
      email: user.email,
      joinedAt: membership.joinedAt,
      billingMode: membership.billingMode,
    });
  }

  return seats;
}

// ---------------------------------------------------------------------------
// Service: Get Practice Invoice — consolidated practice billing only
// ---------------------------------------------------------------------------

/**
 * Returns the practice's consolidated invoice information.
 * Does NOT return individual physician payment records.
 *
 * Calculates from practice membership data and subscription pricing constants.
 */
export async function getPracticeInvoice(
  deps: PracticeServiceDeps,
  practiceId: string,
  adminUserId: string,
): Promise<PracticeInvoiceInfo> {
  // 1. Validate caller is PRACTICE_ADMIN for this practice
  const practice = await deps.practiceRepo.findPracticeById(practiceId);
  if (!practice) {
    throw new NotFoundError('Practice');
  }
  if (practice.adminUserId !== adminUserId) {
    throw new ForbiddenError('Not a practice admin');
  }

  // 2. Get seat counts
  const consolidatedSeatCount = await deps.practiceRepo.getConsolidatedSeatCount(practiceId);
  const totalHeadcount = await deps.practiceRepo.getActiveHeadcount(practiceId);

  // 3. Determine per-seat rate based on billing frequency
  const billingFrequency = practice.billingFrequency;
  const pricingKey = billingFrequency === 'ANNUAL'
    ? SubscriptionPlan.CLINIC_ANNUAL
    : SubscriptionPlan.CLINIC_MONTHLY;

  const pricing = SubscriptionPlanPricing[pricingKey];

  // For annual billing, the per-seat rate displayed is the monthly equivalent
  let perSeatRate: string;
  if (billingFrequency === 'ANNUAL') {
    const annualAmount = parseFloat(pricing.amount);
    const monthlyEquivalent = annualAmount / 12;
    perSeatRate = monthlyEquivalent.toFixed(2);
  } else {
    perSeatRate = pricing.amount;
  }

  // 4. Calculate total amount (consolidated seats only)
  const perSeatValue = parseFloat(pricing.amount);
  const totalValue = consolidatedSeatCount * perSeatValue;
  const totalAmount = totalValue.toFixed(2);

  // 5. Calculate GST
  const gstValue = totalValue * GST_RATE;
  const gstAmount = gstValue.toFixed(2);

  // 6. Next invoice date is the current period end
  const nextInvoiceDate = practice.currentPeriodEnd;

  return {
    totalAmount,
    perSeatRate,
    consolidatedSeatCount,
    totalHeadcount,
    billingFrequency,
    nextInvoiceDate,
    gstAmount,
  };
}
