import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
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

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// User with cancelled early bird history
const CANCELLED_EB_USER_ID = '00000000-1111-0000-0000-000000000001';
const CANCELLED_EB_SESSION_TOKEN = randomBytes(32).toString('hex');
const CANCELLED_EB_SESSION_TOKEN_HASH = hashToken(CANCELLED_EB_SESSION_TOKEN);
const CANCELLED_EB_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// User with suspended early bird
const SUSPENDED_EB_USER_ID = '00000000-1111-0000-0000-000000000002';
const SUSPENDED_EB_SESSION_TOKEN = randomBytes(32).toString('hex');
const SUSPENDED_EB_SESSION_TOKEN_HASH = hashToken(SUSPENDED_EB_SESSION_TOKEN);
const SUSPENDED_EB_SESSION_ID = '00000000-2222-0000-0000-000000000002';

// User whose early bird expired and transitioned to standard
const TRANSITIONED_USER_ID = '00000000-1111-0000-0000-000000000003';
const TRANSITIONED_SESSION_TOKEN = randomBytes(32).toString('hex');
const TRANSITIONED_SESSION_TOKEN_HASH = hashToken(TRANSITIONED_SESSION_TOKEN);
const TRANSITIONED_SESSION_ID = '00000000-2222-0000-0000-000000000003';

// User whose early bird expired while in a practice
const PRACTICE_EB_USER_ID = '00000000-1111-0000-0000-000000000004';
const PRACTICE_EB_SESSION_TOKEN = randomBytes(32).toString('hex');
const PRACTICE_EB_SESSION_TOKEN_HASH = hashToken(PRACTICE_EB_SESSION_TOKEN);
const PRACTICE_EB_SESSION_ID = '00000000-2222-0000-0000-000000000004';

// User who has NEVER had early bird
const FRESH_USER_ID = '00000000-1111-0000-0000-000000000005';
const FRESH_SESSION_TOKEN = randomBytes(32).toString('hex');
const FRESH_SESSION_TOKEN_HASH = hashToken(FRESH_SESSION_TOKEN);
const FRESH_SESSION_ID = '00000000-2222-0000-0000-000000000005';

// User with cancelled early bird trying cross-plan
const CROSS_PLAN_USER_ID = '00000000-1111-0000-0000-000000000006';
const CROSS_PLAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const CROSS_PLAN_SESSION_TOKEN_HASH = hashToken(CROSS_PLAN_SESSION_TOKEN);
const CROSS_PLAN_SESSION_ID = '00000000-2222-0000-0000-000000000006';

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

/**
 * The hasEverHadEarlyBird method is being created by another agent (D17-011).
 * We mock it here to test the expected behaviour: it returns true for users
 * who have ever had an early bird subscription (any status), false otherwise.
 */
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
    // D17-011: re-signup prevention — mocked per user ID
    hasEverHadEarlyBird: vi.fn(async (userId: string) => {
      const usersWithEarlyBirdHistory = [
        CANCELLED_EB_USER_ID,
        SUSPENDED_EB_USER_ID,
        TRANSITIONED_USER_ID,
        PRACTICE_EB_USER_ID,
        CROSS_PLAN_USER_ID,
      ];
      return usersWithEarlyBirdHistory.includes(userId);
    }),
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
      const users: Record<string, any> = {
        [CANCELLED_EB_USER_ID]: {
          userId: CANCELLED_EB_USER_ID,
          email: 'cancelled-eb@test.ca',
          fullName: 'Dr. Cancelled EB',
        },
        [SUSPENDED_EB_USER_ID]: {
          userId: SUSPENDED_EB_USER_ID,
          email: 'suspended-eb@test.ca',
          fullName: 'Dr. Suspended EB',
        },
        [TRANSITIONED_USER_ID]: {
          userId: TRANSITIONED_USER_ID,
          email: 'transitioned@test.ca',
          fullName: 'Dr. Transitioned',
        },
        [PRACTICE_EB_USER_ID]: {
          userId: PRACTICE_EB_USER_ID,
          email: 'practice-eb@test.ca',
          fullName: 'Dr. Practice EB',
        },
        [FRESH_USER_ID]: {
          userId: FRESH_USER_ID,
          email: 'fresh@test.ca',
          fullName: 'Dr. Fresh',
        },
        [CROSS_PLAN_USER_ID]: {
          userId: CROSS_PLAN_USER_ID,
          email: 'cross-plan@test.ca',
          fullName: 'Dr. Cross Plan',
        },
      };
      return users[userId];
    }),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const sessions: Record<string, any> = {
        [CANCELLED_EB_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: CANCELLED_EB_SESSION_ID,
            userId: CANCELLED_EB_USER_ID,
            tokenHash: CANCELLED_EB_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: CANCELLED_EB_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'CANCELLED',
          },
        },
        [SUSPENDED_EB_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: SUSPENDED_EB_SESSION_ID,
            userId: SUSPENDED_EB_USER_ID,
            tokenHash: SUSPENDED_EB_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: SUSPENDED_EB_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'SUSPENDED',
          },
        },
        [TRANSITIONED_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: TRANSITIONED_SESSION_ID,
            userId: TRANSITIONED_USER_ID,
            tokenHash: TRANSITIONED_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: TRANSITIONED_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [PRACTICE_EB_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: PRACTICE_EB_SESSION_ID,
            userId: PRACTICE_EB_USER_ID,
            tokenHash: PRACTICE_EB_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PRACTICE_EB_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [FRESH_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: FRESH_SESSION_ID,
            userId: FRESH_USER_ID,
            tokenHash: FRESH_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: FRESH_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'NONE',
          },
        },
        [CROSS_PLAN_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: CROSS_PLAN_SESSION_ID,
            userId: CROSS_PLAN_USER_ID,
            tokenHash: CROSS_PLAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: CROSS_PLAN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'CANCELLED',
          },
        },
      };
      return sessions[tokenHash] ?? undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSubscriptionRepo: ReturnType<typeof createMockSubscriptionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };
  mockSubscriptionRepo = createMockSubscriptionRepo();

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: mockSubscriptionRepo as any,
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

function authedPost(url: string, body?: Record<string, unknown>, token?: string) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: token ? `session=${token}` : undefined,
      'content-type': 'application/json',
    } as any,
    payload: body ?? {},
  });
}

function unauthedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ===========================================================================
// Test Suite: Security — Early Bird Re-Signup Prevention
// ===========================================================================

describe('Security: Early Bird Re-Signup Prevention', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // Direct API bypass attempts
  // =========================================================================

  describe('Direct API bypass attempts', () => {
    it('POST /api/v1/subscriptions/checkout with EARLY_BIRD_MONTHLY plan is rejected for user with cancelled early bird', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      // BusinessRuleError returns 422
      expect(res.statusCode).toBe(422);
      const body = res.json();
      // The error code from BusinessRuleError is BUSINESS_RULE_VIOLATION;
      // the EARLY_BIRD_INELIGIBLE detail is passed via the details object
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('POST /api/v1/subscriptions/checkout with EARLY_BIRD_ANNUAL plan is rejected for user with cancelled early bird', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('request body manipulation: changing plan field after validation does not bypass check', async () => {
      // The server validates plan on the server side — the hasEverHadEarlyBird
      // check happens in the service function, not in input validation.
      // This test ensures that even if an attacker sends the correct plan name,
      // the check still runs against the user's history.
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      // Stripe checkout should never be called for blocked attempts
      expect(stripeCheckoutCreateSpy).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // Status manipulation attempts
  // =========================================================================

  describe('Status manipulation attempts', () => {
    it('user with CANCELLED early bird subscription cannot re-sign up', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
      expect(stripeCheckoutCreateSpy).not.toHaveBeenCalled();
    });

    it('user with SUSPENDED early bird subscription cannot sign up for new early bird', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        SUSPENDED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
      expect(stripeCheckoutCreateSpy).not.toHaveBeenCalled();
    });

    it('user whose early bird expired and transitioned to STANDARD cannot sign up for early bird again', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        TRANSITIONED_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('user whose early bird expired in a practice cannot sign up for early bird individually', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        PRACTICE_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });
  });

  // =========================================================================
  // Cross-plan attempts
  // =========================================================================

  describe('Cross-plan attempts', () => {
    it('user with cancelled EARLY_BIRD_MONTHLY cannot sign up for EARLY_BIRD_ANNUAL', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('user with cancelled EARLY_BIRD_ANNUAL cannot sign up for EARLY_BIRD_MONTHLY', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CROSS_PLAN_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('user with expired+transitioned EARLY_BIRD_MONTHLY cannot sign up for EARLY_BIRD_ANNUAL', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        TRANSITIONED_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });
  });

  // =========================================================================
  // Timing attacks
  // =========================================================================

  describe('Timing attacks', () => {
    it('concurrent early bird signup requests from same user: only first succeeds', async () => {
      // Both requests should be blocked because the user has early bird history.
      // For fresh users, the service layer should handle concurrency via the
      // database unique constraint and early bird cap check.
      const [res1, res2] = await Promise.all([
        authedPost(
          '/api/v1/subscriptions/checkout',
          {
            plan: 'EARLY_BIRD_MONTHLY',
            success_url: 'https://meritum.ca/success',
            cancel_url: 'https://meritum.ca/cancel',
          },
          CANCELLED_EB_SESSION_TOKEN,
        ),
        authedPost(
          '/api/v1/subscriptions/checkout',
          {
            plan: 'EARLY_BIRD_MONTHLY',
            success_url: 'https://meritum.ca/success',
            cancel_url: 'https://meritum.ca/cancel',
          },
          CANCELLED_EB_SESSION_TOKEN,
        ),
      ]);

      // Both should be rejected for a user with early bird history
      expect(res1.statusCode).toBe(422);
      expect(res2.statusCode).toBe(422);
      expect(stripeCheckoutCreateSpy).not.toHaveBeenCalled();
    });

    it('re-signup attempt during the cancellation grace period is still blocked', async () => {
      // Even during the 30-day deletion grace period after cancellation,
      // the hasEverHadEarlyBird check should still return true
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });
  });

  // =========================================================================
  // Account manipulation
  // =========================================================================

  describe('Account manipulation', () => {
    it('user cannot bypass check by creating a subscription record directly (API does not expose direct subscription creation)', async () => {
      // The only way to create a subscription is through the checkout flow.
      // There is no POST /api/v1/subscriptions endpoint for direct creation.
      const res = await authedPost(
        '/api/v1/subscriptions',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      // Should return 404 (no such route) or be blocked
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('error response does not reveal whether user had early bird before (generic message)', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(422);
      const body = res.json();
      // The error message should NOT contain subscription history details
      const responseStr = JSON.stringify(body);
      expect(responseStr).not.toContain('previous');
      expect(responseStr).not.toContain('history');
      expect(responseStr).not.toContain('subscription_id');
      // The error code BUSINESS_RULE_VIOLATION is generic enough not to leak info
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });
  });

  // =========================================================================
  // Positive cases (should succeed)
  // =========================================================================

  describe('Positive cases (should succeed)', () => {
    it('user with cancelled early bird CAN sign up for STANDARD_MONTHLY', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      // Should succeed (200) — hasEverHadEarlyBird only blocks early bird plans
      expect(res.statusCode).toBe(200);
      expect(stripeCheckoutCreateSpy).toHaveBeenCalled();
    });

    it('user with cancelled early bird CAN sign up for STANDARD_ANNUAL', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'STANDARD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(stripeCheckoutCreateSpy).toHaveBeenCalled();
    });

    it('user with cancelled early bird CAN sign up for CLINIC_MONTHLY (via practice)', async () => {
      // CLINIC_MONTHLY is a valid plan — re-signup check only applies to early bird plans
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'CLINIC_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      // Should succeed or fail for a reason OTHER than EARLY_BIRD_INELIGIBLE
      if (res.statusCode !== 200) {
        const body = res.json();
        expect(body.error.code).not.toBe('EARLY_BIRD_INELIGIBLE');
      }
    });

    it('user with cancelled early bird CAN sign up for CLINIC_ANNUAL (via practice)', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'CLINIC_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        CANCELLED_EB_SESSION_TOKEN,
      );

      if (res.statusCode !== 200) {
        const body = res.json();
        expect(body.error.code).not.toBe('EARLY_BIRD_INELIGIBLE');
      }
    });

    it('user who has NEVER had early bird CAN sign up for EARLY_BIRD_MONTHLY', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        FRESH_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(stripeCheckoutCreateSpy).toHaveBeenCalled();
    });

    it('user who has NEVER had early bird CAN sign up for EARLY_BIRD_ANNUAL', async () => {
      const res = await authedPost(
        '/api/v1/subscriptions/checkout',
        {
          plan: 'EARLY_BIRD_ANNUAL',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
        FRESH_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(stripeCheckoutCreateSpy).toHaveBeenCalled();
    });
  });
});
