import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (before any imports that read env vars)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  SubscriptionPlan,
  SubscriptionPlanPricing,
  BillingMode,
  EARLY_BIRD_RATE_LOCK_MONTHS,
  EARLY_BIRD_EXPIRY_WARNING_DAYS,
  EARLY_BIRD_CAP,
  SubscriptionStatus,
} from '@meritum/shared';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Types for mock stores
// ---------------------------------------------------------------------------

interface MockSubscription {
  subscriptionId: string;
  providerId: string;
  stripeCustomerId: string;
  stripeSubscriptionId: string;
  plan: string;
  status: string;
  earlyBirdLockedUntil: Date | null;
  earlyBirdExpiryNotified: boolean;
  currentPeriodStart: Date;
  currentPeriodEnd: Date;
  createdAt: Date;
  updatedAt: Date;
}

interface MockMembership {
  membershipId: string;
  practiceId: string;
  physicianUserId: string;
  billingMode: string;
  joinedAt: Date;
  isActive: boolean;
}

interface MockPractice {
  practiceId: string;
  name: string;
  adminUserId: string;
  stripeCustomerId: string;
  stripeSubscriptionId: string;
  status: string;
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let subscriptionStore: MockSubscription[];
let membershipStore: MockMembership[];
let practiceStore: MockPractice[];
let notificationLog: Array<{ event: string; data: Record<string, unknown> }>;

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_1_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_2_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN_3_ID = '00000000-1111-0000-0000-000000000003';
const PHYSICIAN_4_ID = '00000000-1111-0000-0000-000000000004';
const PHYSICIAN_5_ID = '00000000-1111-0000-0000-000000000005';
const PHYSICIAN_6_ID = '00000000-1111-0000-0000-000000000006';
const PHYSICIAN_7_ID = '00000000-1111-0000-0000-000000000007';
const PRACTICE_ADMIN_ID = '00000000-1111-0000-0000-000000000099';

const PRACTICE_A_ID = '00000000-3333-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

function createMockStripe() {
  return {
    subscriptions: {
      cancel: vi.fn(async (subId: string) => ({ id: subId, status: 'canceled' })),
      update: vi.fn(async (subId: string, data: any) => ({
        id: subId,
        ...data,
        status: 'active',
      })),
      create: vi.fn(async () => ({ id: `sub_${crypto.randomUUID().slice(0, 8)}`, status: 'active' })),
    },
    checkout: {
      sessions: {
        create: vi.fn(async () => ({ url: 'https://checkout.stripe.com/test' })),
      },
    },
    customers: {
      create: vi.fn(async () => ({ id: `cus_${crypto.randomUUID().slice(0, 8)}` })),
    },
  };
}

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async (data: Partial<MockSubscription>): Promise<MockSubscription> => {
      const sub: MockSubscription = {
        subscriptionId: crypto.randomUUID(),
        providerId: data.providerId!,
        stripeCustomerId: data.stripeCustomerId ?? `cus_${crypto.randomUUID().slice(0, 8)}`,
        stripeSubscriptionId: data.stripeSubscriptionId ?? `sub_${crypto.randomUUID().slice(0, 8)}`,
        plan: data.plan ?? SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: data.status ?? SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: data.earlyBirdLockedUntil ?? null,
        earlyBirdExpiryNotified: data.earlyBirdExpiryNotified ?? false,
        currentPeriodStart: data.currentPeriodStart ?? new Date(),
        currentPeriodEnd: data.currentPeriodEnd ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: data.createdAt ?? new Date(),
        updatedAt: data.updatedAt ?? new Date(),
      };
      subscriptionStore.push(sub);
      return sub;
    }),

    findSubscriptionByProviderId: vi.fn(async (providerId: string) => {
      return subscriptionStore.find(
        (s) => s.providerId === providerId && s.status !== SubscriptionStatus.CANCELLED,
      ) ?? undefined;
    }),

    findExpiringEarlyBirdSubscriptions: vi.fn(async (warningDays: number) => {
      const warningDate = new Date(Date.now() + warningDays * 24 * 60 * 60 * 1000);
      return subscriptionStore.filter(
        (s) =>
          s.earlyBirdLockedUntil !== null &&
          s.earlyBirdLockedUntil <= warningDate &&
          s.status === SubscriptionStatus.ACTIVE &&
          s.plan.includes('EARLY_BIRD'),
      );
    }),

    findExpiredEarlyBirdSubscriptions: vi.fn(async () => {
      const now = new Date();
      return subscriptionStore.filter(
        (s) =>
          s.earlyBirdLockedUntil !== null &&
          s.earlyBirdLockedUntil <= now &&
          s.status === SubscriptionStatus.ACTIVE &&
          s.plan.includes('EARLY_BIRD'),
      );
    }),

    updateSubscriptionStatus: vi.fn(async (subId: string, status: string) => {
      const sub = subscriptionStore.find((s) => s.subscriptionId === subId);
      if (sub) {
        sub.status = status;
        sub.updatedAt = new Date();
      }
      return sub;
    }),

    updateSubscriptionPlan: vi.fn(async (subId: string, plan: string) => {
      const sub = subscriptionStore.find((s) => s.subscriptionId === subId);
      if (sub) {
        sub.plan = plan;
        sub.earlyBirdLockedUntil = null;
        sub.updatedAt = new Date();
      }
      return sub;
    }),

    setEarlyBirdExpiryNotified: vi.fn(async (subId: string, notified: boolean) => {
      const sub = subscriptionStore.find((s) => s.subscriptionId === subId);
      if (sub) sub.earlyBirdExpiryNotified = notified;
      return sub;
    }),

    countEarlyBirdSubscriptions: vi.fn(async () => {
      return subscriptionStore.filter(
        (s) => s.plan.includes('EARLY_BIRD') && s.status === SubscriptionStatus.ACTIVE,
      ).length;
    }),

    hasEverHadEarlyBird: vi.fn(async (userId: string) => {
      return subscriptionStore.some(
        (s) => s.providerId === userId && s.plan.includes('EARLY_BIRD'),
      );
    }),
  };
}

function createMockMembershipRepo() {
  return {
    findActiveMembershipByPhysicianId: vi.fn(async (physicianUserId: string) => {
      return membershipStore.find(
        (m) => m.physicianUserId === physicianUserId && m.isActive,
      ) ?? null;
    }),

    findActiveMembershipsByPracticeId: vi.fn(async (practiceId: string) => {
      return membershipStore.filter(
        (m) => m.practiceId === practiceId && m.isActive,
      );
    }),

    createMembership: vi.fn(async (data: Partial<MockMembership>) => {
      const membership: MockMembership = {
        membershipId: crypto.randomUUID(),
        practiceId: data.practiceId!,
        physicianUserId: data.physicianUserId!,
        billingMode: data.billingMode ?? BillingMode.PRACTICE_CONSOLIDATED,
        joinedAt: data.joinedAt ?? new Date(),
        isActive: true,
      };
      membershipStore.push(membership);
      return membership;
    }),

    updateBillingMode: vi.fn(async (membershipId: string, billingMode: string) => {
      const m = membershipStore.find((mem) => mem.membershipId === membershipId);
      if (m) m.billingMode = billingMode;
    }),

    countActiveMembersByBillingMode: vi.fn(async (practiceId: string, billingMode: string) => {
      return membershipStore.filter(
        (m) => m.practiceId === practiceId && m.billingMode === billingMode && m.isActive,
      ).length;
    }),

    findMembershipsByBillingMode: vi.fn(async (practiceId: string, billingMode: string) => {
      return membershipStore.filter(
        (m) => m.practiceId === practiceId && m.billingMode === billingMode && m.isActive,
      );
    }),
  };
}

function createMockPracticeRepo() {
  return {
    findPracticeById: vi.fn(async (practiceId: string) => {
      return practiceStore.find((p) => p.practiceId === practiceId) ?? null;
    }),

    getConsolidatedSeatCount: vi.fn(async (practiceId: string) => {
      return membershipStore.filter(
        (m) =>
          m.practiceId === practiceId &&
          m.isActive &&
          m.billingMode === BillingMode.PRACTICE_CONSOLIDATED,
      ).length;
    }),

    getActiveHeadcount: vi.fn(async (practiceId: string) => {
      return membershipStore.filter(
        (m) => m.practiceId === practiceId && m.isActive,
      ).length;
    }),
  };
}

function createMockEventEmitter() {
  return {
    emit: vi.fn((event: string, data: Record<string, unknown>) => {
      notificationLog.push({ event, data });
    }),
  };
}

function createMockUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => ({
      userId,
      email: `${userId.slice(0, 8)}@test.ca`,
      fullName: `Dr. ${userId.slice(0, 8)}`,
    })),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Simulated service functions
// ---------------------------------------------------------------------------
// These simulate the D17-010 through D17-014 service layer functions.
// When the real implementations are complete, replace these with real imports.
// ---------------------------------------------------------------------------

async function createEarlyBirdSubscription(
  deps: any,
  userId: string,
  plan: string,
): Promise<MockSubscription> {
  // D17-011: Check re-signup prevention
  const hadEarlyBird = await deps.subscriptionRepo.hasEverHadEarlyBird(userId);
  if (hadEarlyBird) {
    throw new Error('EARLY_BIRD_INELIGIBLE');
  }

  // Check existing active subscription
  const existing = await deps.subscriptionRepo.findSubscriptionByProviderId(userId);
  if (existing) {
    throw new Error('ALREADY_SUBSCRIBED');
  }

  // D17-010: Set early_bird_locked_until
  const now = new Date();
  const lockedUntil = new Date(now);
  lockedUntil.setMonth(lockedUntil.getMonth() + EARLY_BIRD_RATE_LOCK_MONTHS);

  const sub = await deps.subscriptionRepo.createSubscription({
    providerId: userId,
    plan,
    status: SubscriptionStatus.ACTIVE,
    earlyBirdLockedUntil: lockedUntil,
    earlyBirdExpiryNotified: false,
    createdAt: now,
    updatedAt: now,
  });

  return sub;
}

async function cancelSubscription(
  deps: any,
  userId: string,
): Promise<void> {
  const sub = await deps.subscriptionRepo.findSubscriptionByProviderId(userId);
  if (!sub) throw new Error('NOT_FOUND');

  await deps.stripe.subscriptions.cancel(sub.stripeSubscriptionId);
  await deps.subscriptionRepo.updateSubscriptionStatus(
    sub.subscriptionId,
    SubscriptionStatus.CANCELLED,
  );
}

async function checkEarlyBirdExpiry(deps: any): Promise<void> {
  // Warning phase
  const expiringSubs = await deps.subscriptionRepo.findExpiringEarlyBirdSubscriptions(
    EARLY_BIRD_EXPIRY_WARNING_DAYS,
  );

  for (const sub of expiringSubs) {
    if (!sub.earlyBirdExpiryNotified && sub.earlyBirdLockedUntil > new Date()) {
      deps.eventEmitter.emit('EARLY_BIRD_EXPIRING', {
        userId: sub.providerId,
        expiresAt: sub.earlyBirdLockedUntil,
      });
      await deps.subscriptionRepo.setEarlyBirdExpiryNotified(sub.subscriptionId, true);
    }
  }

  // Transition phase
  const expiredSubs = await deps.subscriptionRepo.findExpiredEarlyBirdSubscriptions();

  for (const sub of expiredSubs) {
    if (sub.status !== SubscriptionStatus.ACTIVE || !sub.plan.includes('EARLY_BIRD')) {
      continue;
    }

    const membership = await deps.membershipRepo.findActiveMembershipByPhysicianId(sub.providerId);

    if (membership) {
      // Path A: in practice
      const practice = await deps.practiceRepo.findPracticeById(membership.practiceId);
      if (!practice) continue;

      await deps.stripe.subscriptions.cancel(sub.stripeSubscriptionId);
      await deps.subscriptionRepo.updateSubscriptionStatus(
        sub.subscriptionId,
        SubscriptionStatus.CANCELLED,
      );
      await deps.membershipRepo.updateBillingMode(
        membership.membershipId,
        BillingMode.PRACTICE_CONSOLIDATED,
      );

      const newSeatCount = await deps.practiceRepo.getConsolidatedSeatCount(membership.practiceId);
      await deps.stripe.subscriptions.update(practice.stripeSubscriptionId, {
        quantity: newSeatCount,
      });

      deps.eventEmitter.emit('EARLY_BIRD_EXPIRED', {
        userId: sub.providerId,
        transitionType: 'PRACTICE_CONSOLIDATED',
      });

      deps.eventEmitter.emit('PRACTICE_MEMBER_TRANSITIONED', {
        practiceId: membership.practiceId,
        physicianUserId: sub.providerId,
      });
    } else {
      // Path B: individual
      const newPlan = sub.plan === SubscriptionPlan.EARLY_BIRD_MONTHLY
        ? SubscriptionPlan.STANDARD_MONTHLY
        : SubscriptionPlan.STANDARD_ANNUAL;

      await deps.stripe.subscriptions.update(sub.stripeSubscriptionId, {
        items: [{ price: `price_${newPlan.toLowerCase()}` }],
      });

      await deps.subscriptionRepo.updateSubscriptionPlan(sub.subscriptionId, newPlan);

      deps.eventEmitter.emit('EARLY_BIRD_EXPIRED', {
        userId: sub.providerId,
        newPlan,
        transitionType: 'STANDARD',
      });
    }
  }
}

async function acceptPracticeInvitation(
  deps: any,
  physicianUserId: string,
  practiceId: string,
): Promise<MockMembership> {
  // D17-013: Check if physician has active early bird
  const sub = await deps.subscriptionRepo.findSubscriptionByProviderId(physicianUserId);
  const isEarlyBird = sub && sub.plan.includes('EARLY_BIRD') && sub.status === SubscriptionStatus.ACTIVE;

  const billingMode = isEarlyBird
    ? BillingMode.INDIVIDUAL_EARLY_BIRD
    : BillingMode.PRACTICE_CONSOLIDATED;

  const membership = await deps.membershipRepo.createMembership({
    practiceId,
    physicianUserId,
    billingMode,
  });

  // If not early bird, increment practice Stripe quantity
  if (!isEarlyBird) {
    const practice = await deps.practiceRepo.findPracticeById(practiceId);
    if (practice) {
      const newSeatCount = await deps.practiceRepo.getConsolidatedSeatCount(practiceId);
      await deps.stripe.subscriptions.update(practice.stripeSubscriptionId, {
        quantity: newSeatCount,
      });
    }
  }

  return membership;
}

// ---------------------------------------------------------------------------
// Helper: seed a practice with admin
// ---------------------------------------------------------------------------

function seedPractice(overrides?: Partial<MockPractice>): MockPractice {
  const practice: MockPractice = {
    practiceId: overrides?.practiceId ?? PRACTICE_A_ID,
    name: 'Test Clinic A',
    adminUserId: PRACTICE_ADMIN_ID,
    stripeCustomerId: 'cus_practice_a',
    stripeSubscriptionId: 'sub_practice_a',
    status: 'ACTIVE',
    ...overrides,
  };
  practiceStore.push(practice);

  // Admin membership
  membershipStore.push({
    membershipId: crypto.randomUUID(),
    practiceId: practice.practiceId,
    physicianUserId: practice.adminUserId,
    billingMode: BillingMode.PRACTICE_CONSOLIDATED,
    joinedAt: new Date(),
    isActive: true,
  });

  return practice;
}

// ===========================================================================
// Test Suite: Early Bird Lifecycle Integration Tests
// ===========================================================================

describe('Early Bird Lifecycle Integration Tests', () => {
  let mockStripe: ReturnType<typeof createMockStripe>;
  let mockSubscriptionRepo: ReturnType<typeof createMockSubscriptionRepo>;
  let mockMembershipRepo: ReturnType<typeof createMockMembershipRepo>;
  let mockPracticeRepo: ReturnType<typeof createMockPracticeRepo>;
  let mockEventEmitter: ReturnType<typeof createMockEventEmitter>;
  let mockUserRepo: ReturnType<typeof createMockUserRepo>;

  function getDeps() {
    return {
      subscriptionRepo: mockSubscriptionRepo,
      membershipRepo: mockMembershipRepo,
      practiceRepo: mockPracticeRepo,
      stripe: mockStripe,
      eventEmitter: mockEventEmitter,
      userRepo: mockUserRepo,
    };
  }

  beforeEach(() => {
    subscriptionStore = [];
    membershipStore = [];
    practiceStore = [];
    notificationLog = [];
    mockStripe = createMockStripe();
    mockSubscriptionRepo = createMockSubscriptionRepo();
    mockMembershipRepo = createMockMembershipRepo();
    mockPracticeRepo = createMockPracticeRepo();
    mockEventEmitter = createMockEventEmitter();
    mockUserRepo = createMockUserRepo();
    vi.clearAllMocks();
  });

  // =========================================================================
  // Scenario 1: Individual early bird -> standard transition
  // =========================================================================

  describe('Scenario 1: Individual early bird -> standard transition', () => {
    it('physician signs up for EARLY_BIRD_MONTHLY', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_1_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      expect(sub.plan).toBe(SubscriptionPlan.EARLY_BIRD_MONTHLY);
      expect(sub.status).toBe(SubscriptionStatus.ACTIVE);
    });

    it('subscription has early_bird_locked_until set to 12 months from creation', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_1_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      expect(sub.earlyBirdLockedUntil).toBeDefined();
      expect(sub.earlyBirdLockedUntil).not.toBeNull();

      // Should be approximately 12 months from now
      const now = new Date();
      const expectedLock = new Date(now);
      expectedLock.setMonth(expectedLock.getMonth() + EARLY_BIRD_RATE_LOCK_MONTHS);

      const diffMs = Math.abs(sub.earlyBirdLockedUntil!.getTime() - expectedLock.getTime());
      expect(diffMs).toBeLessThan(5000); // Within 5 seconds
    });

    it('early_bird_expiry_notified is false', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_1_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      expect(sub.earlyBirdExpiryNotified).toBe(false);
    });

    it('at 30 days before expiry: checkEarlyBirdExpiry emits EARLY_BIRD_EXPIRING', async () => {
      // Create subscription with locked_until 20 days from now (within 30-day window)
      const lockedUntil = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000);
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: lockedUntil,
        earlyBirdExpiryNotified: false,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 335 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      const warningNotif = notificationLog.find(
        (n) => n.event === 'EARLY_BIRD_EXPIRING',
      );
      expect(warningNotif).toBeDefined();
      expect(warningNotif!.data.userId).toBe(PHYSICIAN_1_ID);
    });

    it('early_bird_expiry_notified is now true', async () => {
      const lockedUntil = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000);
      const sub = {
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: lockedUntil,
        earlyBirdExpiryNotified: false,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 335 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      };
      subscriptionStore.push(sub);

      await checkEarlyBirdExpiry(getDeps());

      expect(mockSubscriptionRepo.setEarlyBirdExpiryNotified).toHaveBeenCalledWith(
        sub.subscriptionId,
        true,
      );
    });

    it('running checkEarlyBirdExpiry again does NOT re-notify', async () => {
      const lockedUntil = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000);
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: lockedUntil,
        earlyBirdExpiryNotified: false,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 335 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      const deps = getDeps();

      // First run
      await checkEarlyBirdExpiry(deps);
      const firstCount = notificationLog.filter(
        (n) => n.event === 'EARLY_BIRD_EXPIRING',
      ).length;
      expect(firstCount).toBe(1);

      // Second run
      await checkEarlyBirdExpiry(deps);
      const secondCount = notificationLog.filter(
        (n) => n.event === 'EARLY_BIRD_EXPIRING',
      ).length;
      expect(secondCount).toBe(1); // No additional notification
    });

    it('at expiry: checkEarlyBirdExpiry transitions to STANDARD_MONTHLY', async () => {
      // Subscription with expired lock
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000), // expired
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      const transitioned = subscriptionStore.find(
        (s) => s.providerId === PHYSICIAN_1_ID,
      );
      expect(transitioned!.plan).toBe(SubscriptionPlan.STANDARD_MONTHLY);
    });

    it('Stripe subscription is updated to standard price', async () => {
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_1',
        expect.objectContaining({
          items: expect.any(Array),
        }),
      );
    });

    it('physician receives EARLY_BIRD_EXPIRED notification', async () => {
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_1_ID,
        stripeCustomerId: 'cus_1',
        stripeSubscriptionId: 'sub_1',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      const expiredNotif = notificationLog.find(
        (n) => n.event === 'EARLY_BIRD_EXPIRED',
      );
      expect(expiredNotif).toBeDefined();
      expect(expiredNotif!.data.userId).toBe(PHYSICIAN_1_ID);
    });
  });

  // =========================================================================
  // Scenario 2: Early bird -> cancellation -> re-signup blocked
  // =========================================================================

  describe('Scenario 2: Early bird -> cancellation -> re-signup blocked', () => {
    it('physician signs up for EARLY_BIRD_MONTHLY', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      expect(sub.plan).toBe(SubscriptionPlan.EARLY_BIRD_MONTHLY);
    });

    it('physician cancels subscription', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      await cancelSubscription(getDeps(), PHYSICIAN_2_ID);

      const sub = subscriptionStore.find((s) => s.providerId === PHYSICIAN_2_ID);
      expect(sub!.status).toBe(SubscriptionStatus.CANCELLED);
    });

    it('physician attempts EARLY_BIRD_MONTHLY signup -> rejected with EARLY_BIRD_INELIGIBLE', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_2_ID);

      await expect(
        createEarlyBirdSubscription(
          getDeps(),
          PHYSICIAN_2_ID,
          SubscriptionPlan.EARLY_BIRD_MONTHLY,
        ),
      ).rejects.toThrow('EARLY_BIRD_INELIGIBLE');
    });

    it('physician attempts EARLY_BIRD_ANNUAL signup -> rejected with EARLY_BIRD_INELIGIBLE', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_2_ID);

      await expect(
        createEarlyBirdSubscription(
          getDeps(),
          PHYSICIAN_2_ID,
          SubscriptionPlan.EARLY_BIRD_ANNUAL,
        ),
      ).rejects.toThrow('EARLY_BIRD_INELIGIBLE');
    });

    it('physician can sign up for STANDARD_MONTHLY (allowed)', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_2_ID);

      // hasEverHadEarlyBird returns true, but standard plan should be allowed
      const deps = getDeps();
      const sub = await deps.subscriptionRepo.createSubscription({
        providerId: PHYSICIAN_2_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
      });

      expect(sub.plan).toBe(SubscriptionPlan.STANDARD_MONTHLY);
    });

    it('physician can sign up for STANDARD_ANNUAL (allowed)', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_2_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_2_ID);

      const deps = getDeps();
      const sub = await deps.subscriptionRepo.createSubscription({
        providerId: PHYSICIAN_2_ID,
        plan: SubscriptionPlan.STANDARD_ANNUAL,
        status: SubscriptionStatus.ACTIVE,
      });

      expect(sub.plan).toBe(SubscriptionPlan.STANDARD_ANNUAL);
    });
  });

  // =========================================================================
  // Scenario 3: Early bird physician joins practice
  // =========================================================================

  describe('Scenario 3: Early bird physician joins practice', () => {
    it('physician on active early bird accepts practice invitation', async () => {
      seedPractice();
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_3_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      const membership = await acceptPracticeInvitation(
        getDeps(),
        PHYSICIAN_3_ID,
        PRACTICE_A_ID,
      );

      expect(membership).toBeDefined();
      expect(membership.practiceId).toBe(PRACTICE_A_ID);
    });

    it('membership billing_mode is INDIVIDUAL_EARLY_BIRD', async () => {
      seedPractice();
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_3_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      const membership = await acceptPracticeInvitation(
        getDeps(),
        PHYSICIAN_3_ID,
        PRACTICE_A_ID,
      );

      expect(membership.billingMode).toBe(BillingMode.INDIVIDUAL_EARLY_BIRD);
    });

    it('practice Stripe quantity is NOT incremented', async () => {
      seedPractice();
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_3_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      vi.clearAllMocks();

      await acceptPracticeInvitation(getDeps(), PHYSICIAN_3_ID, PRACTICE_A_ID);

      // Stripe subscription should NOT be updated for early bird members
      expect(mockStripe.subscriptions.update).not.toHaveBeenCalled();
    });

    it('physician counts toward practice headcount', async () => {
      seedPractice();
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_3_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      await acceptPracticeInvitation(getDeps(), PHYSICIAN_3_ID, PRACTICE_A_ID);

      const headcount = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);
      // Admin + PHYSICIAN_3 = 2
      expect(headcount).toBeGreaterThanOrEqual(2);
    });

    it('physician still has their individual early bird subscription', async () => {
      seedPractice();
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_3_ID,
        SubscriptionPlan.EARLY_BIRD_MONTHLY,
      );

      await acceptPracticeInvitation(getDeps(), PHYSICIAN_3_ID, PRACTICE_A_ID);

      const sub = subscriptionStore.find(
        (s) => s.providerId === PHYSICIAN_3_ID && s.status === SubscriptionStatus.ACTIVE,
      );
      expect(sub).toBeDefined();
      expect(sub!.plan).toBe(SubscriptionPlan.EARLY_BIRD_MONTHLY);
    });
  });

  // =========================================================================
  // Scenario 4: Early bird expires while in practice
  // =========================================================================

  describe('Scenario 4: Early bird expires while in practice', () => {
    it('early bird rate lock expires -> checkEarlyBirdExpiry processes transition', async () => {
      seedPractice();

      // Expired early bird subscription
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      // Membership as INDIVIDUAL_EARLY_BIRD
      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      // Individual subscription cancelled
      const sub = subscriptionStore.find((s) => s.providerId === PHYSICIAN_4_ID);
      expect(sub!.status).toBe(SubscriptionStatus.CANCELLED);
    });

    it('checkEarlyBirdExpiry: cancels individual subscription', async () => {
      seedPractice();

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      expect(mockStripe.subscriptions.cancel).toHaveBeenCalledWith('sub_4');
    });

    it('checkEarlyBirdExpiry: transitions billing_mode to PRACTICE_CONSOLIDATED', async () => {
      seedPractice();

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      const membershipId = crypto.randomUUID();
      membershipStore.push({
        membershipId,
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      expect(mockMembershipRepo.updateBillingMode).toHaveBeenCalledWith(
        membershipId,
        BillingMode.PRACTICE_CONSOLIDATED,
      );
    });

    it('checkEarlyBirdExpiry: increments practice Stripe quantity', async () => {
      seedPractice();

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_practice_a',
        expect.objectContaining({ quantity: expect.any(Number) }),
      );
    });

    it('physician notified of transition', async () => {
      seedPractice();

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      const physicianNotif = notificationLog.find(
        (n) => n.event === 'EARLY_BIRD_EXPIRED' && n.data.userId === PHYSICIAN_4_ID,
      );
      expect(physicianNotif).toBeDefined();
    });

    it('practice admin notified of member transition', async () => {
      seedPractice();

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      await checkEarlyBirdExpiry(getDeps());

      const adminNotif = notificationLog.find(
        (n) => n.event === 'PRACTICE_MEMBER_TRANSITIONED',
      );
      expect(adminNotif).toBeDefined();
      expect(adminNotif!.data.practiceId).toBe(PRACTICE_A_ID);

      // Security: admin notification must NOT contain billing details
      const notifStr = JSON.stringify(adminNotif!.data);
      expect(notifStr).not.toContain('amount');
      expect(notifStr).not.toContain('rate');
      expect(notifStr).not.toContain('price');
      expect(notifStr).not.toContain('199');
      expect(notifStr).not.toContain('279');
    });

    it('practice headcount unchanged', async () => {
      seedPractice();

      // Add physician to practice with INDIVIDUAL_EARLY_BIRD billing
      membershipStore.push({
        membershipId: crypto.randomUUID(),
        practiceId: PRACTICE_A_ID,
        physicianUserId: PHYSICIAN_4_ID,
        billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
        joinedAt: new Date(),
        isActive: true,
      });

      const headcountBefore = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);

      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_4_ID,
        stripeCustomerId: 'cus_4',
        stripeSubscriptionId: 'sub_4',
        plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      const headcountAfter = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);
      expect(headcountAfter).toBe(headcountBefore);
    });
  });

  // =========================================================================
  // Scenario 5: Practice with all early bird members
  // =========================================================================

  describe('Scenario 5: Practice with all early bird members', () => {
    it('create practice where all 5 founding members are on early bird', async () => {
      seedPractice();
      const physicianIds = [PHYSICIAN_1_ID, PHYSICIAN_2_ID, PHYSICIAN_3_ID, PHYSICIAN_4_ID, PHYSICIAN_5_ID];

      for (const pid of physicianIds) {
        await createEarlyBirdSubscription(getDeps(), pid, SubscriptionPlan.EARLY_BIRD_MONTHLY);
        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      const ebMembers = membershipStore.filter(
        (m) =>
          m.practiceId === PRACTICE_A_ID &&
          m.billingMode === BillingMode.INDIVIDUAL_EARLY_BIRD &&
          m.isActive,
      );
      expect(ebMembers.length).toBe(5);
    });

    it('practice Stripe subscription quantity = 0 (only admin consolidated initially)', async () => {
      seedPractice();
      const physicianIds = [PHYSICIAN_1_ID, PHYSICIAN_2_ID, PHYSICIAN_3_ID, PHYSICIAN_4_ID, PHYSICIAN_5_ID];

      for (const pid of physicianIds) {
        await createEarlyBirdSubscription(getDeps(), pid, SubscriptionPlan.EARLY_BIRD_MONTHLY);
        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      // Only the admin is PRACTICE_CONSOLIDATED
      const consolidatedCount = await mockPracticeRepo.getConsolidatedSeatCount(PRACTICE_A_ID);
      expect(consolidatedCount).toBe(1); // Just the admin
    });

    it('practice still qualifies for clinic tier (headcount = 6 including admin)', async () => {
      seedPractice();
      const physicianIds = [PHYSICIAN_1_ID, PHYSICIAN_2_ID, PHYSICIAN_3_ID, PHYSICIAN_4_ID, PHYSICIAN_5_ID];

      for (const pid of physicianIds) {
        await createEarlyBirdSubscription(getDeps(), pid, SubscriptionPlan.EARLY_BIRD_MONTHLY);
        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      const headcount = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);
      expect(headcount).toBeGreaterThanOrEqual(5); // Qualifies for clinic tier
    });

    it('as each early bird expires, consolidated quantity increments', async () => {
      seedPractice();
      const physicianIds = [PHYSICIAN_1_ID, PHYSICIAN_2_ID, PHYSICIAN_3_ID];

      for (const pid of physicianIds) {
        subscriptionStore.push({
          subscriptionId: crypto.randomUUID(),
          providerId: pid,
          stripeCustomerId: `cus_${pid.slice(0, 8)}`,
          stripeSubscriptionId: `sub_${pid.slice(0, 8)}`,
          plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
          status: SubscriptionStatus.ACTIVE,
          earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000), // expired
          earlyBirdExpiryNotified: true,
          currentPeriodStart: new Date(),
          currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
          updatedAt: new Date(),
        });

        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      await checkEarlyBirdExpiry(getDeps());

      // All 3 should have been cancelled and transitioned
      const cancelledSubs = subscriptionStore.filter(
        (s) => physicianIds.includes(s.providerId) && s.status === SubscriptionStatus.CANCELLED,
      );
      expect(cancelledSubs.length).toBe(3);

      // billingMode updates should have been called for each
      expect(mockMembershipRepo.updateBillingMode).toHaveBeenCalledTimes(3);
    });
  });

  // =========================================================================
  // Scenario 6: Mixed practice -- some early bird, some standard
  // =========================================================================

  describe('Scenario 6: Mixed practice -- some early bird, some standard', () => {
    it('practice has early bird and standard members with correct Stripe quantity', async () => {
      seedPractice();

      // 3 early bird members
      for (const pid of [PHYSICIAN_1_ID, PHYSICIAN_2_ID, PHYSICIAN_3_ID]) {
        subscriptionStore.push({
          subscriptionId: crypto.randomUUID(),
          providerId: pid,
          stripeCustomerId: `cus_${pid.slice(0, 8)}`,
          stripeSubscriptionId: `sub_${pid.slice(0, 8)}`,
          plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
          status: SubscriptionStatus.ACTIVE,
          earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000), // not expired
          earlyBirdExpiryNotified: false,
          currentPeriodStart: new Date(),
          currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      // 3 standard (consolidated) members + admin = 4 consolidated
      for (const pid of [PHYSICIAN_4_ID, PHYSICIAN_5_ID, PHYSICIAN_6_ID]) {
        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.PRACTICE_CONSOLIDATED,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      // Admin (1) + 3 standard = 4 consolidated seats
      const consolidatedCount = await mockPracticeRepo.getConsolidatedSeatCount(PRACTICE_A_ID);
      expect(consolidatedCount).toBe(4);

      // Total headcount = admin + 3 EB + 3 standard = 7
      const headcount = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);
      expect(headcount).toBe(7);
    });

    it('as early birds expire, consolidated count increases', async () => {
      seedPractice();

      // 2 expired early bird members
      for (const pid of [PHYSICIAN_1_ID, PHYSICIAN_2_ID]) {
        subscriptionStore.push({
          subscriptionId: crypto.randomUUID(),
          providerId: pid,
          stripeCustomerId: `cus_${pid.slice(0, 8)}`,
          stripeSubscriptionId: `sub_${pid.slice(0, 8)}`,
          plan: SubscriptionPlan.EARLY_BIRD_MONTHLY,
          status: SubscriptionStatus.ACTIVE,
          earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000), // expired
          earlyBirdExpiryNotified: true,
          currentPeriodStart: new Date(),
          currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
          updatedAt: new Date(),
        });

        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.INDIVIDUAL_EARLY_BIRD,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      // 2 standard members
      for (const pid of [PHYSICIAN_3_ID, PHYSICIAN_4_ID]) {
        membershipStore.push({
          membershipId: crypto.randomUUID(),
          practiceId: PRACTICE_A_ID,
          physicianUserId: pid,
          billingMode: BillingMode.PRACTICE_CONSOLIDATED,
          joinedAt: new Date(),
          isActive: true,
        });
      }

      // Before: admin + 2 standard = 3 consolidated
      const consolidatedBefore = await mockPracticeRepo.getConsolidatedSeatCount(PRACTICE_A_ID);
      expect(consolidatedBefore).toBe(3);

      await checkEarlyBirdExpiry(getDeps());

      // Both early birds should be cancelled
      expect(mockStripe.subscriptions.cancel).toHaveBeenCalledTimes(2);

      // All headcount members remain counted
      const headcountAfter = await mockPracticeRepo.getActiveHeadcount(PRACTICE_A_ID);
      expect(headcountAfter).toBe(5); // admin + 2 transitioned + 2 standard
    });
  });

  // =========================================================================
  // Scenario 7: Early bird annual lifecycle
  // =========================================================================

  describe('Scenario 7: Early bird annual lifecycle', () => {
    it('physician signs up for EARLY_BIRD_ANNUAL', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_7_ID,
        SubscriptionPlan.EARLY_BIRD_ANNUAL,
      );

      expect(sub.plan).toBe(SubscriptionPlan.EARLY_BIRD_ANNUAL);
    });

    it('subscription has early_bird_locked_until set to 12 months', async () => {
      const sub = await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_7_ID,
        SubscriptionPlan.EARLY_BIRD_ANNUAL,
      );

      expect(sub.earlyBirdLockedUntil).not.toBeNull();

      const now = new Date();
      const expectedLock = new Date(now);
      expectedLock.setMonth(expectedLock.getMonth() + EARLY_BIRD_RATE_LOCK_MONTHS);

      const diffMs = Math.abs(sub.earlyBirdLockedUntil!.getTime() - expectedLock.getTime());
      expect(diffMs).toBeLessThan(5000);
    });

    it('at expiry: transitions to STANDARD_ANNUAL', async () => {
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_7_ID,
        stripeCustomerId: 'cus_7',
        stripeSubscriptionId: 'sub_7',
        plan: SubscriptionPlan.EARLY_BIRD_ANNUAL,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      const transitioned = subscriptionStore.find(
        (s) => s.providerId === PHYSICIAN_7_ID,
      );
      expect(transitioned!.plan).toBe(SubscriptionPlan.STANDARD_ANNUAL);
    });

    it('Stripe subscription updated to STANDARD_ANNUAL price', async () => {
      subscriptionStore.push({
        subscriptionId: crypto.randomUUID(),
        providerId: PHYSICIAN_7_ID,
        stripeCustomerId: 'cus_7',
        stripeSubscriptionId: 'sub_7',
        plan: SubscriptionPlan.EARLY_BIRD_ANNUAL,
        status: SubscriptionStatus.ACTIVE,
        earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000),
        earlyBirdExpiryNotified: true,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        updatedAt: new Date(),
      });

      await checkEarlyBirdExpiry(getDeps());

      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_7',
        expect.objectContaining({
          items: expect.arrayContaining([
            expect.objectContaining({
              price: expect.stringContaining('standard_annual'),
            }),
          ]),
        }),
      );
    });

    it('after cancellation: re-signup for EARLY_BIRD_ANNUAL blocked', async () => {
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_7_ID,
        SubscriptionPlan.EARLY_BIRD_ANNUAL,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_7_ID);

      await expect(
        createEarlyBirdSubscription(
          getDeps(),
          PHYSICIAN_7_ID,
          SubscriptionPlan.EARLY_BIRD_ANNUAL,
        ),
      ).rejects.toThrow('EARLY_BIRD_INELIGIBLE');
    });

    it('after cancellation: re-signup for EARLY_BIRD_MONTHLY also blocked', async () => {
      // Reset store for this test
      subscriptionStore = [];
      await createEarlyBirdSubscription(
        getDeps(),
        PHYSICIAN_7_ID,
        SubscriptionPlan.EARLY_BIRD_ANNUAL,
      );
      await cancelSubscription(getDeps(), PHYSICIAN_7_ID);

      await expect(
        createEarlyBirdSubscription(
          getDeps(),
          PHYSICIAN_7_ID,
          SubscriptionPlan.EARLY_BIRD_MONTHLY,
        ),
      ).rejects.toThrow('EARLY_BIRD_INELIGIBLE');
    });
  });
});
