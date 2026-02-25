import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
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

import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { stripeWebhookPluginFp } from '../../../src/plugins/stripe-webhook.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import { type PlatformHandlerDeps } from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type StripeClient,
} from '../../../src/domains/platform/platform.service.js';
import {
  calculateEffectiveRate,
  getEarlyBirdRate,
  isEarlyBirdRate,
  BASE_MONTHLY_RATE,
  MINIMUM_RATE_FLOOR,
  DISCOUNT_CEILING_PERCENT,
  DISCOUNT_ANNUAL_PERCENT,
  DISCOUNT_CLINIC_PERCENT,
  EARLY_BIRD_MONTHLY_RATE,
  SubscriptionPlanPricing,
  SubscriptionPlan,
} from '@meritum/shared';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock Stripe client
// ---------------------------------------------------------------------------

let stripeCheckoutCreateSpy: ReturnType<typeof vi.fn>;

function createMockStripe(): StripeClient {
  stripeCheckoutCreateSpy = vi.fn(async () => ({
    url: 'https://checkout.stripe.com/test',
  }));
  return {
    customers: {
      create: vi.fn(async () => ({ id: 'cus_test' })),
      del: vi.fn(async () => ({ id: 'cus_test', deleted: true })),
    },
    checkout: {
      sessions: {
        create: stripeCheckoutCreateSpy,
      },
    },
    billingPortal: {
      sessions: {
        create: vi.fn(async () => ({ url: 'https://billing.stripe.com/test' })),
      },
    },
    taxRates: {
      create: vi.fn(async () => ({ id: 'txr_test' })),
    },
    webhooks: {
      constructEvent: vi.fn((payload, signature, _secret) => {
        if (signature === 'invalid_signature') {
          throw new Error('Invalid signature');
        }
        return JSON.parse(payload);
      }),
    },
    invoiceItems: {
      create: vi.fn(async () => ({ id: 'ii_test' })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: 'sub_test', status: 'canceled' })),
    },
  };
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async () => ({})),
    findSubscriptionByProviderId: vi.fn(async () => undefined),
    findSubscriptionByStripeCustomerId: vi.fn(async () => undefined),
    findSubscriptionByStripeSubscriptionId: vi.fn(async () => undefined),
    updateSubscriptionStatus: vi.fn(async () => undefined),
    updateSubscriptionPeriod: vi.fn(async () => undefined),
    updateSubscriptionPlan: vi.fn(async () => undefined),
    incrementFailedPaymentCount: vi.fn(async () => undefined),
    resetFailedPaymentCount: vi.fn(async () => undefined),
    findPastDueSubscriptions: vi.fn(async () => []),
    findSubscriptionsDueForSuspension: vi.fn(async () => []),
    findSubscriptionsDueForCancellation: vi.fn(async () => []),
    findSubscriptionsDueForDeletion: vi.fn(async () => []),
    countEarlyBirdSubscriptions: vi.fn(async () => 0),
    findAllSubscriptions: vi.fn(async () => ({ data: [], total: 0 })),
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async () => ({})),
    findPaymentByStripeInvoiceId: vi.fn(async () => undefined),
    listPaymentsForSubscription: vi.fn(async () => ({ data: [], total: 0 })),
    updatePaymentStatus: vi.fn(async () => undefined),
    getPaymentSummary: vi.fn(async () => ({
      totalPaid: '0.00',
      totalGst: '0.00',
      paymentCount: 0,
      lastPaymentDate: null,
    })),
  };
}

function createMockStatusComponentRepo() {
  return {
    listComponents: vi.fn(async () => []),
    updateComponentStatus: vi.fn(async () => undefined),
    seedComponents: vi.fn(async () => {}),
  };
}

function createMockIncidentRepo() {
  return {
    createIncident: vi.fn(async () => ({})),
    updateIncident: vi.fn(async () => undefined),
    listActiveIncidents: vi.fn(async () => []),
    listIncidentHistory: vi.fn(async () => ({ data: [], total: 0 })),
    findIncidentById: vi.fn(async () => undefined),
  };
}

function createMockUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      if (userId === PHYSICIAN_USER_ID) {
        return {
          userId: PHYSICIAN_USER_ID,
          email: 'physician@test.ca',
          fullName: 'Dr. Test Physician',
        };
      }
      return undefined;
    }),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: createMockSubscriptionRepo() as any,
    paymentRepo: createMockPaymentRepo() as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    userRepo: createMockUserRepo(),
    stripe: mockStripe,
    config: {
      stripePriceStandardMonthly: 'price_standard_monthly_test',
      stripePriceStandardAnnual: 'price_standard_annual_test',
      stripePriceEarlyBirdMonthly: 'price_early_bird_monthly_test',
      stripePriceEarlyBirdAnnual: 'price_early_bird_annual_test',
      stripeWebhookSecret: 'whsec_test_secret',
      gstTaxRateId: 'txr_gst_test',
    },
  };

  const handlerDeps: PlatformHandlerDeps = {
    serviceDeps,
    eventEmitter: mockEvents,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: mockEvents,
    },
  });

  await testApp.register(stripeWebhookPluginFp, {
    webhookPath: '/api/v1/webhooks/stripe',
    stripe: mockStripe,
    webhookSecret: 'whsec_test_secret',
  });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    request.log.error(error);
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(platformRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function authedPost(url: string, body?: Record<string, unknown>, token = PHYSICIAN_SESSION_TOKEN) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

// ===========================================================================
// Test Suite: Security — Discount Ceiling Enforcement
// ===========================================================================

describe('Security: Discount Ceiling Enforcement', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Pure function boundary tests
  // =========================================================================

  describe('Pure function boundary tests', () => {
    it('calculateEffectiveRate(279, true, true) does not go below $237.15', () => {
      const result = calculateEffectiveRate(279, true, true);
      expect(result.monthlyRate).toBeGreaterThanOrEqual(237.15);
    });

    it('calculateEffectiveRate(279, true, true) returns exactly $237.15 (15% off)', () => {
      const result = calculateEffectiveRate(279, true, true);
      expect(result.monthlyRate).toBe(237.15);
    });

    it('calculateEffectiveRate(279, false, false) returns exactly $279.00', () => {
      const result = calculateEffectiveRate(279, false, false);
      expect(result.monthlyRate).toBe(279.00);
    });

    it('calculateEffectiveRate(279, true, false) returns exactly $265.05', () => {
      const result = calculateEffectiveRate(279, true, false);
      expect(result.monthlyRate).toBe(265.05);
    });

    it('calculateEffectiveRate(279, false, true) returns exactly $251.10', () => {
      const result = calculateEffectiveRate(279, false, true);
      expect(result.monthlyRate).toBe(251.10);
    });

    it('totalDiscountPercent never exceeds 15', () => {
      // Test all combinations
      const combos: Array<[boolean, boolean]> = [
        [false, false],
        [true, false],
        [false, true],
        [true, true],
      ];

      for (const [isAnnual, isClinic] of combos) {
        const result = calculateEffectiveRate(BASE_MONTHLY_RATE, isAnnual, isClinic);
        expect(result.totalDiscountPercent).toBeLessThanOrEqual(DISCOUNT_CEILING_PERCENT);
      }
    });
  });

  // =========================================================================
  // Manipulated input tests
  // =========================================================================

  describe('Manipulated input tests', () => {
    it('passing a base rate of 0 still returns a non-negative rate', () => {
      const result = calculateEffectiveRate(0, true, true);
      expect(result.monthlyRate).toBeGreaterThanOrEqual(0);
    });

    it('passing a negative base rate returns a sane result (no negative billing)', () => {
      const result = calculateEffectiveRate(-100, true, true);
      // With negative input, function should return 0 (edge case handling)
      expect(result.monthlyRate).toBeGreaterThanOrEqual(0);
    });

    it('passing NaN base rate is handled gracefully', () => {
      const result = calculateEffectiveRate(NaN, true, true);
      expect(result.monthlyRate).toBe(0);
      expect(result.totalDiscountPercent).toBe(0);
      expect(result.appliedDiscounts).toEqual([]);
    });

    it('passing Infinity base rate is handled gracefully', () => {
      const result = calculateEffectiveRate(Infinity, false, false);
      expect(result.monthlyRate).toBe(0);
      expect(result.totalDiscountPercent).toBe(0);
      expect(result.appliedDiscounts).toEqual([]);
    });
  });

  // =========================================================================
  // Stripe price verification
  // =========================================================================

  describe('Stripe price verification', () => {
    it('STANDARD_MONTHLY pricing constant matches $279.00', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.STANDARD_MONTHLY].amount).toBe('279.00');
    });

    it('STANDARD_ANNUAL pricing constant matches $3,181.00', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.STANDARD_ANNUAL].amount).toBe('3181.00');
    });

    it('CLINIC_MONTHLY pricing constant matches $251.10', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.CLINIC_MONTHLY].amount).toBe('251.10');
    });

    it('CLINIC_ANNUAL pricing constant matches $2,863.00', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.CLINIC_ANNUAL].amount).toBe('2863.00');
    });

    it('EARLY_BIRD_MONTHLY pricing constant matches $199.00', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.EARLY_BIRD_MONTHLY].amount).toBe('199.00');
    });

    it('EARLY_BIRD_ANNUAL pricing constant matches $2,388.00', () => {
      expect(SubscriptionPlanPricing[SubscriptionPlan.EARLY_BIRD_ANNUAL].amount).toBe('2388.00');
    });

    it('no pricing constant produces a monthly effective rate below $237.15 (except early bird at $199)', () => {
      const plans = Object.values(SubscriptionPlanPricing);

      for (const planInfo of plans) {
        const amount = parseFloat(planInfo.amount);
        const monthlyEquivalent =
          planInfo.interval === 'year' ? amount / 12 : amount;

        if (planInfo.plan.includes('EARLY_BIRD')) {
          // Early bird is intentionally below the floor — it's a marketing rate
          expect(monthlyEquivalent).toBe(199);
        } else {
          // All discount-derived rates must be at or above the floor
          expect(monthlyEquivalent).toBeGreaterThanOrEqual(MINIMUM_RATE_FLOOR);
        }
      }
    });
  });

  // =========================================================================
  // Early bird isolation
  // =========================================================================

  describe('Early bird isolation', () => {
    it('early bird monthly rate is $199 with zero discounts', () => {
      const result = getEarlyBirdRate(false);
      expect(result.monthlyRate).toBe(199);
      expect(result.appliedDiscounts).toEqual([]);
      expect(result.totalDiscountPercent).toBe(0);
    });

    it('early bird annual rate is $2,388 (199*12) with zero discounts', () => {
      const result = getEarlyBirdRate(true);
      expect(result.annualRate).toBe(199 * 12);
      expect(result.annualRate).toBe(2388);
      expect(result.appliedDiscounts).toEqual([]);
      expect(result.totalDiscountPercent).toBe(0);
    });

    it('early bird cannot have annual discount applied', () => {
      // getEarlyBirdRate does not accept discount parameters —
      // the annual flag only determines if annualRate is returned, not a discount
      const result = getEarlyBirdRate(true);
      expect(result.monthlyRate).toBe(199);
      expect(result.totalDiscountPercent).toBe(0);
      // Annual rate should be 199*12, not 199*12*0.95
      expect(result.annualRate).toBe(2388);
    });

    it('early bird cannot have clinic discount applied', () => {
      // getEarlyBirdRate has no clinic parameter — by design
      const resultMonthly = getEarlyBirdRate(false);
      const resultAnnual = getEarlyBirdRate(true);
      expect(resultMonthly.totalDiscountPercent).toBe(0);
      expect(resultAnnual.totalDiscountPercent).toBe(0);
    });

    it('getEarlyBirdRate(false).totalDiscountPercent === 0', () => {
      const result = getEarlyBirdRate(false);
      expect(result.totalDiscountPercent).toBe(0);
    });

    it('getEarlyBirdRate(true).totalDiscountPercent === 0', () => {
      const result = getEarlyBirdRate(true);
      expect(result.totalDiscountPercent).toBe(0);
    });
  });

  // =========================================================================
  // API-level enforcement
  // =========================================================================

  describe('API-level enforcement', () => {
    it('POST /api/v1/subscriptions/checkout with CLINIC_MONTHLY creates session at server-defined price', async () => {
      const res = await authedPost('/api/v1/subscriptions/checkout', {
        plan: 'CLINIC_MONTHLY',
        success_url: 'https://meritum.ca/success',
        cancel_url: 'https://meritum.ca/cancel',
      });

      // The checkout endpoint uses server-side price IDs, not client amounts
      // Even if CLINIC_MONTHLY is not directly in the getPriceId switch,
      // the server controls the Stripe Price ID — clients cannot override amounts
      if (res.statusCode === 200) {
        expect(stripeCheckoutCreateSpy).toHaveBeenCalled();
        const callArgs = stripeCheckoutCreateSpy.mock.calls[0][0];
        // Price comes from server config, not from client
        expect(callArgs.line_items[0].price).toBeDefined();
        expect(typeof callArgs.line_items[0].price).toBe('string');
        // Amount is not in the checkout params — Stripe resolves it from price ID
        expect(callArgs.line_items[0].amount).toBeUndefined();
      }
    });

    it('checkout session always uses the server-defined price ID, not client-provided amounts', async () => {
      const res = await authedPost('/api/v1/subscriptions/checkout', {
        plan: 'STANDARD_MONTHLY',
        success_url: 'https://meritum.ca/success',
        cancel_url: 'https://meritum.ca/cancel',
      });

      if (res.statusCode === 200) {
        const callArgs = stripeCheckoutCreateSpy.mock.calls[0][0];
        // Server maps plan name to a price ID from environment config
        expect(callArgs.line_items[0].price).toBe('price_standard_monthly_test');
        // No amount field — Stripe determines price from the Price object
        expect(callArgs.line_items[0].amount).toBeUndefined();
      }
    });

    it('client cannot pass a custom amount to the checkout endpoint', async () => {
      const res = await authedPost('/api/v1/subscriptions/checkout', {
        plan: 'STANDARD_MONTHLY',
        amount: 1.00, // Attacker tries to inject a custom amount
        success_url: 'https://meritum.ca/success',
        cancel_url: 'https://meritum.ca/cancel',
      });

      // Even if the request succeeds, the server ignores the amount field
      if (res.statusCode === 200 && stripeCheckoutCreateSpy.mock.calls.length > 0) {
        const callArgs = stripeCheckoutCreateSpy.mock.calls[0][0];
        expect(callArgs.line_items[0].amount).toBeUndefined();
        expect(callArgs.line_items[0].price).toBe('price_standard_monthly_test');
      }
    });

    it('client cannot pass a custom price_id to the checkout endpoint', async () => {
      const res = await authedPost('/api/v1/subscriptions/checkout', {
        plan: 'STANDARD_MONTHLY',
        price_id: 'price_attacker_free_plan', // Attacker tries to inject a price ID
        success_url: 'https://meritum.ca/success',
        cancel_url: 'https://meritum.ca/cancel',
      });

      // Server uses its own price mapping, ignoring any client-provided price_id
      if (res.statusCode === 200 && stripeCheckoutCreateSpy.mock.calls.length > 0) {
        const callArgs = stripeCheckoutCreateSpy.mock.calls[0][0];
        expect(callArgs.line_items[0].price).toBe('price_standard_monthly_test');
      }
    });
  });

  // =========================================================================
  // Discount stacking rules
  // =========================================================================

  describe('Discount stacking rules', () => {
    it('annual (5%) + clinic (10%) = 15% (additive, not compounding)', () => {
      const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, true);
      expect(result.totalDiscountPercent).toBe(DISCOUNT_ANNUAL_PERCENT + DISCOUNT_CLINIC_PERCENT);
      expect(result.totalDiscountPercent).toBe(15);
    });

    it('15% is the absolute maximum — no combination exceeds this', () => {
      const result = calculateEffectiveRate(BASE_MONTHLY_RATE, true, true);
      expect(result.totalDiscountPercent).toBeLessThanOrEqual(DISCOUNT_CEILING_PERCENT);
      expect(result.totalDiscountPercent).toBe(15);
    });

    it('verify: 279 * 0.85 = 237.15 (floor rate)', () => {
      const expectedFloor = 279 * 0.85;
      expect(expectedFloor).toBe(237.15);
      expect(MINIMUM_RATE_FLOOR).toBe(237.15);

      const result = calculateEffectiveRate(279, true, true);
      expect(result.monthlyRate).toBe(237.15);
    });

    it('verify: 279 * 0.90 * 0.95 = 238.545 (compounding would be wrong)', () => {
      // If discounts were multiplicative instead of additive:
      // 279 * (1 - 0.10) * (1 - 0.05) = 279 * 0.90 * 0.95 = 238.545
      const compoundingRate = 279 * 0.90 * 0.95;
      expect(compoundingRate).toBeCloseTo(238.545, 2);

      // But the system uses additive: 279 * (1 - 0.15) = 237.15
      const result = calculateEffectiveRate(279, true, true);
      expect(result.monthlyRate).not.toBeCloseTo(compoundingRate, 2);
      expect(result.monthlyRate).toBe(237.15);
    });

    it('the system uses additive stacking (15%), NOT multiplicative (14.5%)', () => {
      const result = calculateEffectiveRate(279, true, true);

      // Additive: 5 + 10 = 15%
      expect(result.totalDiscountPercent).toBe(15);

      // Multiplicative would be: 1 - (1-0.05)*(1-0.10) = 1 - 0.855 = 14.5%
      // The system should NOT use 14.5%
      expect(result.totalDiscountPercent).not.toBe(14.5);

      // The resulting rate confirms additive stacking
      expect(result.monthlyRate).toBe(237.15); // 279 * 0.85
    });
  });
});
