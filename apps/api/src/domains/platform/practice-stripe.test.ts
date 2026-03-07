import crypto from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createPracticeStripeSubscription,
  updatePracticeStripeQuantity,
  cancelPracticeStripeSubscription,
  handlePracticeStripeWebhook,
  type PracticeStripeServiceDeps,
} from './practice-stripe.service.js';
import type { PracticeStripeClient } from './practice.service.js';

// ---------------------------------------------------------------------------
// Mock the shared constants module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/platform.constants.js', async () => {
  return {
    GST_RATE: 0.05,
    SubscriptionPlan: {
      STANDARD_MONTHLY: 'STANDARD_MONTHLY',
      STANDARD_ANNUAL: 'STANDARD_ANNUAL',
      EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
      EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
      CLINIC_MONTHLY: 'CLINIC_MONTHLY',
      CLINIC_ANNUAL: 'CLINIC_ANNUAL',
    },
    BillingMode: {
      PRACTICE_CONSOLIDATED: 'PRACTICE_CONSOLIDATED',
      INDIVIDUAL_EARLY_BIRD: 'INDIVIDUAL_EARLY_BIRD',
    },
    PracticeStatus: {
      ACTIVE: 'ACTIVE',
      SUSPENDED: 'SUSPENDED',
      CANCELLED: 'CANCELLED',
    },
    PracticeInvitationStatus: {
      PENDING: 'PENDING',
      ACCEPTED: 'ACCEPTED',
      DECLINED: 'DECLINED',
      EXPIRED: 'EXPIRED',
    },
    PRACTICE_INVITATION_EXPIRY_DAYS: 7,
    CLINIC_MINIMUM_PHYSICIANS: 5,
    DISCOUNT_ANNUAL: 0.05,
    DISCOUNT_CLINIC: 0.10,
    DISCOUNT_CEILING: 0.15,
    SubscriptionPlanPricing: {
      CLINIC_MONTHLY: {
        plan: 'CLINIC_MONTHLY',
        amount: '251.10',
        interval: 'month',
        label: 'Clinic Monthly',
      },
      CLINIC_ANNUAL: {
        plan: 'CLINIC_ANNUAL',
        amount: '2863.00',
        interval: 'year',
        label: 'Clinic Annual',
      },
    },
  };
});

vi.mock('@meritum/shared/constants/iam.constants.js', async () => {
  return {
    Role: {
      PHYSICIAN: 'PHYSICIAN',
      DELEGATE: 'DELEGATE',
      ADMIN: 'ADMIN',
      PRACTICE_ADMIN: 'PRACTICE_ADMIN',
    },
    SubscriptionStatus: {
      TRIAL: 'TRIAL',
      ACTIVE: 'ACTIVE',
      PAST_DUE: 'PAST_DUE',
      SUSPENDED: 'SUSPENDED',
      CANCELLED: 'CANCELLED',
    },
  };
});

vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  return {
    practices: { __table: 'practices' },
    practiceMemberships: { __table: 'practice_memberships' },
    practiceInvitations: { __table: 'practice_invitations' },
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PRACTICE_ID = crypto.randomUUID();
const ADMIN_EMAIL = 'admin@testclinic.ca';
const PRACTICE_NAME = 'Test Medical Clinic';
const STRIPE_CUSTOMER_ID = 'cus_test123';
const STRIPE_SUBSCRIPTION_ID = 'sub_test456';
const PRICE_MONTHLY = 'price_clinic_monthly_abc';
const PRICE_ANNUAL = 'price_clinic_annual_xyz';

function makeMockStripe(): PracticeStripeClient {
  return {
    customers: {
      create: vi.fn().mockResolvedValue({ id: STRIPE_CUSTOMER_ID }),
    },
    subscriptions: {
      cancel: vi.fn().mockResolvedValue({ id: STRIPE_SUBSCRIPTION_ID, status: 'canceled' }),
      update: vi.fn().mockResolvedValue({ id: STRIPE_SUBSCRIPTION_ID, quantity: 5 }),
      create: vi.fn().mockResolvedValue({ id: STRIPE_SUBSCRIPTION_ID, status: 'active' }),
    },
  };
}

function makeMockPracticeRepo(overrides: Record<string, any> = {}): any {
  return {
    findPracticeById: vi.fn().mockResolvedValue({
      practiceId: PRACTICE_ID,
      name: PRACTICE_NAME,
      adminUserId: crypto.randomUUID(),
      stripeCustomerId: STRIPE_CUSTOMER_ID,
      stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
      billingFrequency: 'MONTHLY',
      status: 'ACTIVE',
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      createdAt: new Date(),
      updatedAt: new Date(),
    }),
    updatePracticeStripeIds: vi.fn().mockResolvedValue(undefined),
    updatePracticeStatus: vi.fn().mockResolvedValue(undefined),
    getConsolidatedSeatCount: vi.fn().mockResolvedValue(5),
    getActiveHeadcount: vi.fn().mockResolvedValue(7),
    ...overrides,
  };
}

function makeDeps(overrides: {
  stripe?: PracticeStripeClient;
  practiceRepo?: any;
  env?: { STRIPE_PRICE_CLINIC_MONTHLY: string; STRIPE_PRICE_CLINIC_ANNUAL: string };
} = {}): PracticeStripeServiceDeps {
  return {
    stripe: overrides.stripe ?? makeMockStripe(),
    practiceRepo: overrides.practiceRepo ?? makeMockPracticeRepo(),
    env: overrides.env ?? {
      STRIPE_PRICE_CLINIC_MONTHLY: PRICE_MONTHLY,
      STRIPE_PRICE_CLINIC_ANNUAL: PRICE_ANNUAL,
    },
  };
}

// ===========================================================================
// Tests: createPracticeStripeSubscription
// ===========================================================================

describe('createPracticeStripeSubscription', () => {
  let deps: PracticeStripeServiceDeps;

  beforeEach(() => {
    deps = makeDeps();
  });

  it('creates a Stripe customer with practice name and admin email (ZERO PHI)', async () => {
    const result = await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'MONTHLY',
      5,
    );

    expect(deps.stripe.customers.create).toHaveBeenCalledWith({
      name: PRACTICE_NAME,
      email: ADMIN_EMAIL,
      metadata: { practice_id: PRACTICE_ID },
    });
    expect(result.stripeCustomerId).toBe(STRIPE_CUSTOMER_ID);
  });

  it('creates a monthly subscription with the correct price ID', async () => {
    await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'MONTHLY',
      5,
    );

    expect(deps.stripe.subscriptions!.create).toHaveBeenCalledWith({
      customer: STRIPE_CUSTOMER_ID,
      items: [{ price: PRICE_MONTHLY, quantity: 5 }],
      metadata: { practice_id: PRACTICE_ID },
    });
  });

  it('creates an annual subscription with the correct price ID', async () => {
    await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'ANNUAL',
      8,
    );

    expect(deps.stripe.subscriptions!.create).toHaveBeenCalledWith({
      customer: STRIPE_CUSTOMER_ID,
      items: [{ price: PRICE_ANNUAL, quantity: 8 }],
      metadata: { practice_id: PRACTICE_ID },
    });
  });

  it('uses consolidatedSeatCount as quantity, NOT total headcount', async () => {
    const consolidatedSeats = 3;

    await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'MONTHLY',
      consolidatedSeats,
    );

    const createCall = (deps.stripe.subscriptions!.create as any).mock.calls[0][0];
    expect(createCall.items[0].quantity).toBe(3);
  });

  it('persists Stripe IDs on the practice record', async () => {
    const result = await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'MONTHLY',
      5,
    );

    expect(deps.practiceRepo.updatePracticeStripeIds).toHaveBeenCalledWith(
      PRACTICE_ID,
      STRIPE_CUSTOMER_ID,
      STRIPE_SUBSCRIPTION_ID,
    );
    expect(result.stripeSubscriptionId).toBe(STRIPE_SUBSCRIPTION_ID);
  });

  it('throws if subscriptions.create is not available', async () => {
    deps.stripe.subscriptions = {
      cancel: vi.fn().mockResolvedValue({ id: 'sub_x', status: 'canceled' }),
      update: vi.fn().mockResolvedValue({ id: 'sub_x', quantity: 1 }),
      // create is intentionally missing
    };

    await expect(
      createPracticeStripeSubscription(
        deps,
        PRACTICE_ID,
        ADMIN_EMAIL,
        PRACTICE_NAME,
        'MONTHLY',
        5,
      ),
    ).rejects.toThrow('Stripe subscriptions.create is not available');
  });

  it('does NOT send any PHI to Stripe — only name and email in customer.create', async () => {
    await createPracticeStripeSubscription(
      deps,
      PRACTICE_ID,
      ADMIN_EMAIL,
      PRACTICE_NAME,
      'MONTHLY',
      5,
    );

    const customerCreateArgs = (deps.stripe.customers.create as any).mock.calls[0][0];
    // Verify only name, email, and metadata are present — no PHI fields
    expect(Object.keys(customerCreateArgs).sort()).toEqual(
      ['email', 'metadata', 'name'].sort(),
    );
    // Metadata only contains practice_id, no patient data
    expect(customerCreateArgs.metadata).toEqual({ practice_id: PRACTICE_ID });
  });
});

// ===========================================================================
// Tests: updatePracticeStripeQuantity
// ===========================================================================

describe('updatePracticeStripeQuantity', () => {
  let deps: PracticeStripeServiceDeps;

  beforeEach(() => {
    deps = makeDeps();
  });

  it('updates subscription quantity with proration', async () => {
    await updatePracticeStripeQuantity(deps, PRACTICE_ID, 7);

    expect(deps.stripe.subscriptions!.update).toHaveBeenCalledWith(
      STRIPE_SUBSCRIPTION_ID,
      {
        quantity: 7,
        proration_behavior: 'create_prorations',
      },
    );
  });

  it('looks up the practice to get stripeSubscriptionId', async () => {
    await updatePracticeStripeQuantity(deps, PRACTICE_ID, 3);

    expect(deps.practiceRepo.findPracticeById).toHaveBeenCalledWith(PRACTICE_ID);
  });

  it('throws if practice not found', async () => {
    const repo = makeMockPracticeRepo({ findPracticeById: vi.fn().mockResolvedValue(null) });
    deps = makeDeps({ practiceRepo: repo });

    await expect(
      updatePracticeStripeQuantity(deps, PRACTICE_ID, 5),
    ).rejects.toThrow(`Practice not found: ${PRACTICE_ID}`);
  });

  it('throws if practice has no Stripe subscription', async () => {
    const repo = makeMockPracticeRepo({
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId: PRACTICE_ID,
        stripeSubscriptionId: null,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        status: 'ACTIVE',
      }),
    });
    deps = makeDeps({ practiceRepo: repo });

    await expect(
      updatePracticeStripeQuantity(deps, PRACTICE_ID, 5),
    ).rejects.toThrow(`Practice ${PRACTICE_ID} has no Stripe subscription`);
  });

  it('throws if stripe.subscriptions is not available', async () => {
    const mockStripe = makeMockStripe();
    mockStripe.subscriptions = undefined;
    deps = makeDeps({ stripe: mockStripe });

    await expect(
      updatePracticeStripeQuantity(deps, PRACTICE_ID, 5),
    ).rejects.toThrow('Stripe subscriptions API is not available');
  });
});

// ===========================================================================
// Tests: cancelPracticeStripeSubscription
// ===========================================================================

describe('cancelPracticeStripeSubscription', () => {
  let deps: PracticeStripeServiceDeps;

  beforeEach(() => {
    deps = makeDeps();
  });

  it('cancels the Stripe subscription for the practice', async () => {
    await cancelPracticeStripeSubscription(deps, PRACTICE_ID);

    expect(deps.stripe.subscriptions!.cancel).toHaveBeenCalledWith(
      STRIPE_SUBSCRIPTION_ID,
    );
  });

  it('looks up the practice to get stripeSubscriptionId', async () => {
    await cancelPracticeStripeSubscription(deps, PRACTICE_ID);

    expect(deps.practiceRepo.findPracticeById).toHaveBeenCalledWith(PRACTICE_ID);
  });

  it('throws if practice not found', async () => {
    const repo = makeMockPracticeRepo({ findPracticeById: vi.fn().mockResolvedValue(null) });
    deps = makeDeps({ practiceRepo: repo });

    await expect(
      cancelPracticeStripeSubscription(deps, PRACTICE_ID),
    ).rejects.toThrow(`Practice not found: ${PRACTICE_ID}`);
  });

  it('throws if practice has no Stripe subscription', async () => {
    const repo = makeMockPracticeRepo({
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId: PRACTICE_ID,
        stripeSubscriptionId: null,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        status: 'ACTIVE',
      }),
    });
    deps = makeDeps({ practiceRepo: repo });

    await expect(
      cancelPracticeStripeSubscription(deps, PRACTICE_ID),
    ).rejects.toThrow(`Practice ${PRACTICE_ID} has no Stripe subscription`);
  });

  it('throws if stripe.subscriptions is not available', async () => {
    const mockStripe = makeMockStripe();
    mockStripe.subscriptions = undefined;
    deps = makeDeps({ stripe: mockStripe });

    await expect(
      cancelPracticeStripeSubscription(deps, PRACTICE_ID),
    ).rejects.toThrow('Stripe subscriptions API is not available');
  });
});

// ===========================================================================
// Tests: handlePracticeStripeWebhook
// ===========================================================================

describe('handlePracticeStripeWebhook', () => {
  let deps: PracticeStripeServiceDeps & { practiceRepo: any };

  beforeEach(() => {
    const base = makeDeps();
    deps = {
      ...base,
      practiceRepo: base.practiceRepo,
    };
  });

  // -------------------------------------------------------------------------
  // Routing: practice_id metadata check
  // -------------------------------------------------------------------------

  it('ignores events without practice_id in metadata', async () => {
    const event = {
      type: 'invoice.paid',
      data: { object: { metadata: {} } },
    };

    await handlePracticeStripeWebhook(deps, event);

    // No repo calls should have been made
    expect(deps.practiceRepo.findPracticeById).not.toHaveBeenCalled();
    expect(deps.practiceRepo.updatePracticeStatus).not.toHaveBeenCalled();
  });

  it('ignores events with no metadata at all', async () => {
    const event = {
      type: 'invoice.paid',
      data: { object: {} },
    };

    await handlePracticeStripeWebhook(deps, event);

    expect(deps.practiceRepo.findPracticeById).not.toHaveBeenCalled();
  });

  it('ignores unknown event types for practice context', async () => {
    const event = {
      type: 'some.unknown.event',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);

    // Should not interact with repo for unknown events
    expect(deps.practiceRepo.findPracticeById).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // invoice.created — GST handling
  // -------------------------------------------------------------------------

  it('adds GST (5%) to invoice.created event', async () => {
    const obj: any = {
      metadata: { practice_id: PRACTICE_ID },
      subtotal: 100_00, // $100.00 in cents
    };
    const event = { type: 'invoice.created', data: { object: obj } };

    await handlePracticeStripeWebhook(deps, event);

    expect(obj.tax).toBe(500); // 5% of 10000 = 500 cents
    expect(obj.total).toBe(100_00 + 500);
  });

  it('handles zero subtotal on invoice.created', async () => {
    const obj: any = {
      metadata: { practice_id: PRACTICE_ID },
      subtotal: 0,
    };
    const event = { type: 'invoice.created', data: { object: obj } };

    await handlePracticeStripeWebhook(deps, event);

    expect(obj.tax).toBe(0);
    expect(obj.total).toBe(0);
  });

  it('handles missing subtotal on invoice.created', async () => {
    const obj: any = {
      metadata: { practice_id: PRACTICE_ID },
    };
    const event = { type: 'invoice.created', data: { object: obj } };

    await handlePracticeStripeWebhook(deps, event);

    expect(obj.tax).toBe(0);
    expect(obj.total).toBe(0);
  });

  // -------------------------------------------------------------------------
  // invoice.paid
  // -------------------------------------------------------------------------

  it('reactivates a suspended practice on invoice.paid', async () => {
    deps.practiceRepo.findPracticeById = vi.fn().mockResolvedValue({
      practiceId: PRACTICE_ID,
      status: 'SUSPENDED',
    });

    const event = {
      type: 'invoice.paid',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);

    expect(deps.practiceRepo.updatePracticeStatus).toHaveBeenCalledWith(
      PRACTICE_ID,
      'ACTIVE',
    );
  });

  it('does not update status if practice is already ACTIVE on invoice.paid', async () => {
    deps.practiceRepo.findPracticeById = vi.fn().mockResolvedValue({
      practiceId: PRACTICE_ID,
      status: 'ACTIVE',
    });

    const event = {
      type: 'invoice.paid',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);

    expect(deps.practiceRepo.updatePracticeStatus).not.toHaveBeenCalled();
  });

  it('handles practice not found on invoice.paid gracefully', async () => {
    deps.practiceRepo.findPracticeById = vi.fn().mockResolvedValue(null);

    const event = {
      type: 'invoice.paid',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    // Should not throw
    await handlePracticeStripeWebhook(deps, event);
    expect(deps.practiceRepo.updatePracticeStatus).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // invoice.payment_failed
  // -------------------------------------------------------------------------

  it('suspends practice on invoice.payment_failed', async () => {
    const event = {
      type: 'invoice.payment_failed',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);

    expect(deps.practiceRepo.updatePracticeStatus).toHaveBeenCalledWith(
      PRACTICE_ID,
      'SUSPENDED',
    );
  });

  it('handles practice not found on invoice.payment_failed gracefully', async () => {
    deps.practiceRepo.findPracticeById = vi.fn().mockResolvedValue(null);

    const event = {
      type: 'invoice.payment_failed',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);
    expect(deps.practiceRepo.updatePracticeStatus).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // customer.subscription.deleted
  // -------------------------------------------------------------------------

  it('marks practice as CANCELLED on subscription.deleted', async () => {
    const event = {
      type: 'customer.subscription.deleted',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);

    expect(deps.practiceRepo.updatePracticeStatus).toHaveBeenCalledWith(
      PRACTICE_ID,
      'CANCELLED',
    );
  });

  it('handles practice not found on subscription.deleted gracefully', async () => {
    deps.practiceRepo.findPracticeById = vi.fn().mockResolvedValue(null);

    const event = {
      type: 'customer.subscription.deleted',
      data: { object: { metadata: { practice_id: PRACTICE_ID } } },
    };

    await handlePracticeStripeWebhook(deps, event);
    expect(deps.practiceRepo.updatePracticeStatus).not.toHaveBeenCalled();
  });
});
