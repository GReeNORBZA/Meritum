import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

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
// Fixed test identities — two isolated physicians + admin
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);
const PHYSICIAN1_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Physician 2 — "other" physician (attacker perspective)
const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);
const PHYSICIAN2_SESSION_ID = '00000000-2222-0000-0000-000000000002';

// Admin — can see all subscriptions
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Subscription data for each physician
// ---------------------------------------------------------------------------

const SUBSCRIPTION1_ID = '00000000-3333-0000-0000-000000000001';
const SUBSCRIPTION2_ID = '00000000-3333-0000-0000-000000000002';

const STRIPE_CUSTOMER1_ID = 'cus_physician1_test';
const STRIPE_CUSTOMER2_ID = 'cus_physician2_test';
const STRIPE_SUB1_ID = 'sub_physician1_test';
const STRIPE_SUB2_ID = 'sub_physician2_test';

const subscription1 = {
  subscriptionId: SUBSCRIPTION1_ID,
  providerId: PHYSICIAN1_USER_ID,
  stripeCustomerId: STRIPE_CUSTOMER1_ID,
  stripeSubscriptionId: STRIPE_SUB1_ID,
  plan: 'STANDARD_MONTHLY',
  status: 'ACTIVE',
  currentPeriodStart: new Date('2026-01-01'),
  currentPeriodEnd: new Date('2026-02-01'),
  failedPaymentCount: 0,
  suspendedAt: null,
  cancelledAt: null,
  deletionScheduledAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
};

const subscription2 = {
  subscriptionId: SUBSCRIPTION2_ID,
  providerId: PHYSICIAN2_USER_ID,
  stripeCustomerId: STRIPE_CUSTOMER2_ID,
  stripeSubscriptionId: STRIPE_SUB2_ID,
  plan: 'STANDARD_ANNUAL',
  status: 'ACTIVE',
  currentPeriodStart: new Date('2026-01-15'),
  currentPeriodEnd: new Date('2027-01-15'),
  failedPaymentCount: 0,
  suspendedAt: null,
  cancelledAt: null,
  deletionScheduledAt: null,
  createdAt: new Date('2026-01-15'),
  updatedAt: new Date('2026-01-15'),
};

// ---------------------------------------------------------------------------
// Payment data for each physician
// ---------------------------------------------------------------------------

const PAYMENT1_ID = '00000000-6666-0000-0000-000000000001';
const PAYMENT2_ID = '00000000-6666-0000-0000-000000000002';

const payment1 = {
  paymentId: PAYMENT1_ID,
  subscriptionId: SUBSCRIPTION1_ID,
  stripeInvoiceId: 'inv_physician1_001',
  amountCad: '279.00',
  gstAmount: '13.95',
  totalCad: '292.95',
  status: 'PAID',
  paidAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01'),
};

const payment2 = {
  paymentId: PAYMENT2_ID,
  subscriptionId: SUBSCRIPTION2_ID,
  stripeInvoiceId: 'inv_physician2_001',
  amountCad: '2790.00',
  gstAmount: '139.50',
  totalCad: '2929.50',
  status: 'PAID',
  paidAt: new Date('2026-01-15'),
  createdAt: new Date('2026-01-15'),
};

// ---------------------------------------------------------------------------
// Mock Stripe client
// ---------------------------------------------------------------------------

function createMockStripe(): StripeClient {
  return {
    customers: {
      create: vi.fn(async () => ({ id: 'cus_test' })),
      del: vi.fn(async () => ({ id: 'cus_test', deleted: true })),
    },
    checkout: {
      sessions: {
        create: vi.fn(async () => ({ url: 'https://checkout.stripe.com/test' })),
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
// Mock repositories — scoped data stores
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async (data: any) => {
      return { subscriptionId: randomUUID(), ...data };
    }),
    findSubscriptionByProviderId: vi.fn(async (providerId: string) => {
      // Return subscription scoped to the requesting physician
      if (providerId === PHYSICIAN1_USER_ID) return { ...subscription1 };
      if (providerId === PHYSICIAN2_USER_ID) return { ...subscription2 };
      return undefined;
    }),
    findSubscriptionByStripeCustomerId: vi.fn(async (customerId: string) => {
      if (customerId === STRIPE_CUSTOMER1_ID) return { ...subscription1 };
      if (customerId === STRIPE_CUSTOMER2_ID) return { ...subscription2 };
      return undefined;
    }),
    findSubscriptionByStripeSubscriptionId: vi.fn(
      async (subscriptionId: string) => {
        if (subscriptionId === STRIPE_SUB1_ID) return { ...subscription1 };
        if (subscriptionId === STRIPE_SUB2_ID) return { ...subscription2 };
        return undefined;
      },
    ),
    updateSubscriptionStatus: vi.fn(async (subscriptionId: string, status: string) => {
      if (subscriptionId === SUBSCRIPTION1_ID) {
        return { ...subscription1, status };
      }
      if (subscriptionId === SUBSCRIPTION2_ID) {
        return { ...subscription2, status };
      }
      return undefined;
    }),
    updateSubscriptionPeriod: vi.fn(async () => undefined),
    updateSubscriptionPlan: vi.fn(async () => undefined),
    incrementFailedPaymentCount: vi.fn(async () => undefined),
    resetFailedPaymentCount: vi.fn(async () => undefined),
    findPastDueSubscriptions: vi.fn(async () => []),
    findSubscriptionsDueForSuspension: vi.fn(async () => []),
    findSubscriptionsDueForCancellation: vi.fn(async () => []),
    findSubscriptionsDueForDeletion: vi.fn(async () => []),
    countEarlyBirdSubscriptions: vi.fn(async () => 0),
    findAllSubscriptions: vi.fn(async () => ({
      data: [{ ...subscription1 }, { ...subscription2 }],
      total: 2,
    })),
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async (data: any) => {
      return { paymentId: randomUUID(), ...data };
    }),
    findPaymentByStripeInvoiceId: vi.fn(async () => undefined),
    listPaymentsForSubscription: vi.fn(
      async (subscriptionId: string, _opts: any) => {
        // Return payments only for the matching subscription
        if (subscriptionId === SUBSCRIPTION1_ID) {
          return { data: [{ ...payment1 }], total: 1 };
        }
        if (subscriptionId === SUBSCRIPTION2_ID) {
          return { data: [{ ...payment2 }], total: 1 };
        }
        return { data: [], total: 0 };
      },
    ),
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
      if (userId === PHYSICIAN1_USER_ID) {
        return {
          userId: PHYSICIAN1_USER_ID,
          email: 'physician1@test.ca',
          fullName: 'Dr. Physician One',
        };
      }
      if (userId === PHYSICIAN2_USER_ID) {
        return {
          userId: PHYSICIAN2_USER_ID,
          email: 'physician2@test.ca',
          fullName: 'Dr. Physician Two',
        };
      }
      return undefined;
    }),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock session repository — supports two physicians + admin
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      // Physician 1
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN1_SESSION_ID,
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }

      // Physician 2
      if (tokenHash === PHYSICIAN2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN2_SESSION_ID,
            userId: PHYSICIAN2_USER_ID,
            tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN2_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }

      // Admin
      if (tokenHash === ADMIN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: ADMIN_SESSION_ID,
            userId: ADMIN_USER_ID,
            tokenHash: ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: ADMIN_USER_ID,
            role: 'ADMIN',
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
let mockSubscriptionRepo: ReturnType<typeof createMockSubscriptionRepo>;
let mockPaymentRepo: ReturnType<typeof createMockPaymentRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };

  mockSubscriptionRepo = createMockSubscriptionRepo();
  mockPaymentRepo = createMockPaymentRepo();

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: mockSubscriptionRepo as any,
    paymentRepo: mockPaymentRepo as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    userRepo: createMockUserRepo(),
    stripe: mockStripe,
    config: {
      stripePriceStandardMonthly: 'price_monthly_test',
      stripePriceStandardAnnual: 'price_annual_test',
      stripePriceEarlyBirdMonthly: 'price_earlybird_test',
      stripeWebhookSecret: 'whsec_test_secret',
    },
  };

  const handlerDeps: PlatformHandlerDeps = {
    serviceDeps,
    eventEmitter: mockEvents,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: mockEvents,
    },
  });

  // Register Stripe webhook plugin
  await testApp.register(stripeWebhookPluginFp, {
    webhookPath: '/api/v1/webhooks/stripe',
    stripe: mockStripe,
    webhookSecret: 'whsec_test_secret',
  });

  // Error handler
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

  // Register platform routes
  await testApp.register(platformRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Platform Physician Tenant Isolation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Subscription isolation: GET /subscriptions/current
  // =========================================================================

  describe('GET /api/v1/subscriptions/current — subscription is scoped to authenticated user', () => {
    it('physician1 sees only their own subscription', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.plan).toBe('STANDARD_MONTHLY');
      expect(body.data.status).toBe('ACTIVE');

      // Verify the repo was called with physician1's userId
      expect(mockSubscriptionRepo.findSubscriptionByProviderId).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
      );
    });

    it('physician2 sees only their own subscription', async () => {
      mockSubscriptionRepo.findSubscriptionByProviderId.mockClear();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.plan).toBe('STANDARD_ANNUAL');
      expect(body.data.status).toBe('ACTIVE');

      // Verify the repo was called with physician2's userId — NOT physician1's
      expect(mockSubscriptionRepo.findSubscriptionByProviderId).toHaveBeenCalledWith(
        PHYSICIAN2_USER_ID,
      );
    });

    it('physician1 cannot see physician2 subscription data in their response', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // Must not contain physician2's identifiers
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain(SUBSCRIPTION2_ID);
      expect(rawBody).not.toContain(STRIPE_CUSTOMER2_ID);
      expect(rawBody).not.toContain(STRIPE_SUB2_ID);
      expect(rawBody).not.toContain('STANDARD_ANNUAL');
    });

    it('physician2 cannot see physician1 subscription data in their response', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // Must not contain physician1's identifiers
      expect(rawBody).not.toContain(PHYSICIAN1_USER_ID);
      expect(rawBody).not.toContain(SUBSCRIPTION1_ID);
      expect(rawBody).not.toContain(STRIPE_CUSTOMER1_ID);
      expect(rawBody).not.toContain(STRIPE_SUB1_ID);
    });
  });

  // =========================================================================
  // Payment history isolation: GET /subscriptions/payments
  // =========================================================================

  describe('GET /api/v1/subscriptions/payments — payment history is scoped to authenticated user', () => {
    it('physician1 sees only their own payment history', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBe(1);
      expect(body.data[0].subscriptionId).toBe(SUBSCRIPTION1_ID);
      expect(body.data[0].amountCad).toBe('279.00');

      // Verify payment repo was called with physician1's subscription ID
      expect(mockPaymentRepo.listPaymentsForSubscription).toHaveBeenCalledWith(
        SUBSCRIPTION1_ID,
        expect.any(Object),
      );
    });

    it('physician2 sees only their own payment history', async () => {
      mockPaymentRepo.listPaymentsForSubscription.mockClear();

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBe(1);
      expect(body.data[0].subscriptionId).toBe(SUBSCRIPTION2_ID);
      expect(body.data[0].amountCad).toBe('2790.00');

      // Verify payment repo was called with physician2's subscription ID
      expect(mockPaymentRepo.listPaymentsForSubscription).toHaveBeenCalledWith(
        SUBSCRIPTION2_ID,
        expect.any(Object),
      );
    });

    it('physician1 cannot see physician2 payment data in their response', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // Must not contain physician2's payment identifiers
      expect(rawBody).not.toContain(PAYMENT2_ID);
      expect(rawBody).not.toContain(SUBSCRIPTION2_ID);
      expect(rawBody).not.toContain('2790.00');
      expect(rawBody).not.toContain('139.50');
      expect(rawBody).not.toContain('inv_physician2_001');
    });

    it('physician2 cannot see physician1 payment data in their response', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // Must not contain physician1's payment identifiers
      expect(rawBody).not.toContain(PAYMENT1_ID);
      expect(rawBody).not.toContain(SUBSCRIPTION1_ID);
      expect(rawBody).not.toContain('inv_physician1_001');
    });
  });

  // =========================================================================
  // Subscription query path: repo is always called with authenticated user
  // =========================================================================

  describe('Subscription lookup always uses authenticated user ID from session context', () => {
    it('findSubscriptionByProviderId is never called with a different user ID', async () => {
      mockSubscriptionRepo.findSubscriptionByProviderId.mockClear();

      // Physician1 request
      await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      // Verify it was only called with physician1's ID
      const calls =
        mockSubscriptionRepo.findSubscriptionByProviderId.mock.calls;
      for (const call of calls) {
        expect(call[0]).toBe(PHYSICIAN1_USER_ID);
        expect(call[0]).not.toBe(PHYSICIAN2_USER_ID);
      }
    });

    it('portal session uses authenticated user subscription, not arbitrary IDs', async () => {
      mockSubscriptionRepo.findSubscriptionByProviderId.mockClear();

      await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { return_url: 'https://meritum.ca/settings' },
      });

      // Verify the subscription lookup used physician1's ID
      const calls =
        mockSubscriptionRepo.findSubscriptionByProviderId.mock.calls;
      expect(calls.length).toBeGreaterThan(0);
      for (const call of calls) {
        expect(call[0]).toBe(PHYSICIAN1_USER_ID);
      }
    });
  });

  // =========================================================================
  // Admin can see all subscriptions (authorized cross-tenant)
  // =========================================================================

  describe('Admin CAN see all subscriptions via GET /api/v1/admin/subscriptions', () => {
    it('admin receives data for all physicians', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBe(2);

      // Admin sees both subscriptions
      const providerIds = body.data.map((s: any) => s.providerId);
      expect(providerIds).toContain(PHYSICIAN1_USER_ID);
      expect(providerIds).toContain(PHYSICIAN2_USER_ID);
    });

    it('admin can filter by status', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions?status=ACTIVE',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();

      // Verify findAllSubscriptions was called with status filter
      expect(mockSubscriptionRepo.findAllSubscriptions).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'ACTIVE' }),
      );
    });
  });

  // =========================================================================
  // Admin CAN update any subscription status
  // =========================================================================

  describe('Admin CAN update any subscription status', () => {
    it('admin can update physician1 subscription status', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION1_ID}/status`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: { status: 'SUSPENDED' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();

      // Verify the update was called for the correct subscription
      expect(mockSubscriptionRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION1_ID,
        'SUSPENDED',
      );
    });

    it('admin can update physician2 subscription status', async () => {
      mockSubscriptionRepo.updateSubscriptionStatus.mockClear();

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION2_ID}/status`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: { status: 'SUSPENDED' },
      });

      expect(res.statusCode).toBe(200);
      expect(mockSubscriptionRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
        SUBSCRIPTION2_ID,
        'SUSPENDED',
      );
    });

    it('physician cannot access admin status update endpoint', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION1_ID}/status`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: { status: 'SUSPENDED' },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Physician cannot access admin subscription listing
  // =========================================================================

  describe('Physician cannot see other physicians via admin endpoints', () => {
    it('physician1 cannot access GET /api/v1/admin/subscriptions', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician2 cannot access GET /api/v1/admin/subscriptions', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${PHYSICIAN2_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Webhook isolation: events only affect the target physician
  // =========================================================================

  describe('Webhook events only affect the target physician subscription', () => {
    it('checkout.session.completed for physician1 only creates physician1 subscription', async () => {
      mockSubscriptionRepo.createSubscription.mockClear();
      mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId.mockResolvedValueOnce(
        undefined,
      );

      const event = {
        id: 'evt_scope_test_1',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN1_USER_ID,
              plan: 'STANDARD_MONTHLY',
            },
            customer: 'cus_new_physician1',
            subscription: 'sub_new_physician1',
          },
        },
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: event,
        headers: {
          'stripe-signature': 'valid_test_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(200);

      // Verify subscription was created with physician1's userId
      if (mockSubscriptionRepo.createSubscription.mock.calls.length > 0) {
        const createCall = mockSubscriptionRepo.createSubscription.mock.calls[0][0];
        expect(createCall.providerId).toBe(PHYSICIAN1_USER_ID);
        expect(createCall.providerId).not.toBe(PHYSICIAN2_USER_ID);
      }
    });

    it('invoice.paid for physician1 Stripe customer does not affect physician2', async () => {
      mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId.mockClear();

      // Reset: return physician1's subscription when looked up by Stripe sub ID
      mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId.mockImplementation(
        async (subId: string) => {
          if (subId === STRIPE_SUB1_ID) return { ...subscription1 };
          if (subId === STRIPE_SUB2_ID) return { ...subscription2 };
          return undefined;
        },
      );

      const event = {
        id: 'evt_scope_test_2',
        type: 'invoice.paid',
        data: {
          object: {
            id: 'inv_scope_test_p1',
            subscription: STRIPE_SUB1_ID,
            amount_paid: 29295,
            tax: 1395,
            total: 29295,
            currency: 'cad',
          },
        },
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: event,
        headers: {
          'stripe-signature': 'valid_test_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(200);

      // Verify the subscription lookup used physician1's Stripe sub ID
      expect(
        mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId,
      ).toHaveBeenCalledWith(STRIPE_SUB1_ID);

      // If payment was recorded, it should be for subscription1
      if (mockPaymentRepo.recordPayment.mock.calls.length > 0) {
        const paymentCall = mockPaymentRepo.recordPayment.mock.calls[0][0];
        expect(paymentCall.subscriptionId).toBe(SUBSCRIPTION1_ID);
        expect(paymentCall.subscriptionId).not.toBe(SUBSCRIPTION2_ID);
      }
    });

    it('invoice.payment_failed for physician2 does not affect physician1', async () => {
      mockSubscriptionRepo.incrementFailedPaymentCount.mockClear();
      mockSubscriptionRepo.updateSubscriptionStatus.mockClear();
      mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId.mockImplementation(
        async (subId: string) => {
          if (subId === STRIPE_SUB1_ID) return { ...subscription1 };
          if (subId === STRIPE_SUB2_ID) return { ...subscription2 };
          return undefined;
        },
      );

      const event = {
        id: 'evt_scope_test_3',
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: 'inv_scope_test_p2_fail',
            subscription: STRIPE_SUB2_ID,
            amount_due: 292950,
          },
        },
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: event,
        headers: {
          'stripe-signature': 'valid_test_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(200);

      // Verify the lookup was for physician2's subscription
      expect(
        mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId,
      ).toHaveBeenCalledWith(STRIPE_SUB2_ID);

      // If status was updated, verify it targeted physician2's subscription
      if (mockSubscriptionRepo.updateSubscriptionStatus.mock.calls.length > 0) {
        const updateCall =
          mockSubscriptionRepo.updateSubscriptionStatus.mock.calls[0];
        expect(updateCall[0]).toBe(SUBSCRIPTION2_ID);
        expect(updateCall[0]).not.toBe(SUBSCRIPTION1_ID);
      }

      // If failed count was incremented, verify it targeted physician2's subscription
      if (mockSubscriptionRepo.incrementFailedPaymentCount.mock.calls.length > 0) {
        const incCall =
          mockSubscriptionRepo.incrementFailedPaymentCount.mock.calls[0];
        expect(incCall[0]).toBe(SUBSCRIPTION2_ID);
        expect(incCall[0]).not.toBe(SUBSCRIPTION1_ID);
      }
    });

    it('subscription.deleted for physician1 does not affect physician2', async () => {
      mockSubscriptionRepo.updateSubscriptionStatus.mockClear();
      mockSubscriptionRepo.findSubscriptionByStripeSubscriptionId.mockImplementation(
        async (subId: string) => {
          if (subId === STRIPE_SUB1_ID) return { ...subscription1 };
          if (subId === STRIPE_SUB2_ID) return { ...subscription2 };
          return undefined;
        },
      );

      const event = {
        id: 'evt_scope_test_4',
        type: 'customer.subscription.deleted',
        data: {
          object: {
            id: STRIPE_SUB1_ID,
            customer: STRIPE_CUSTOMER1_ID,
          },
        },
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: event,
        headers: {
          'stripe-signature': 'valid_test_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(200);

      // If subscription status was updated, it should only be physician1's
      if (mockSubscriptionRepo.updateSubscriptionStatus.mock.calls.length > 0) {
        const updateCall =
          mockSubscriptionRepo.updateSubscriptionStatus.mock.calls[0];
        expect(updateCall[0]).toBe(SUBSCRIPTION1_ID);
        expect(updateCall[0]).not.toBe(SUBSCRIPTION2_ID);
      }
    });
  });

  // =========================================================================
  // No subscription leakage in error scenarios
  // =========================================================================

  describe('No cross-tenant leakage in error scenarios', () => {
    it('checkout for physician with existing subscription returns error without leaking other subscription data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
        payload: {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      // May return 409 (conflict — already has subscription) or similar
      // Regardless of status, response must not contain physician2 data
      const rawBody = res.body;
      expect(rawBody).not.toContain(PHYSICIAN2_USER_ID);
      expect(rawBody).not.toContain(SUBSCRIPTION2_ID);
      expect(rawBody).not.toContain(STRIPE_CUSTOMER2_ID);
      expect(rawBody).not.toContain('physician2');
    });

    it('payment history for user with no subscription returns empty, not other user data', async () => {
      // Temporarily override to simulate no subscription for a user
      const originalImpl =
        mockSubscriptionRepo.findSubscriptionByProviderId.getMockImplementation();

      mockSubscriptionRepo.findSubscriptionByProviderId.mockImplementation(
        async (providerId: string) => {
          if (providerId === PHYSICIAN1_USER_ID) return undefined; // No subscription
          if (providerId === PHYSICIAN2_USER_ID) return { ...subscription2 };
          return undefined;
        },
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
      expect(body.pagination.total).toBe(0);

      // Must not contain physician2 payment data
      const rawBody = res.body;
      expect(rawBody).not.toContain(SUBSCRIPTION2_ID);
      expect(rawBody).not.toContain('2790.00');
      expect(rawBody).not.toContain('inv_physician2_001');

      // Restore original implementation
      if (originalImpl) {
        mockSubscriptionRepo.findSubscriptionByProviderId.mockImplementation(
          originalImpl,
        );
      } else {
        mockSubscriptionRepo.findSubscriptionByProviderId.mockImplementation(
          async (providerId: string) => {
            if (providerId === PHYSICIAN1_USER_ID) return { ...subscription1 };
            if (providerId === PHYSICIAN2_USER_ID) return { ...subscription2 };
            return undefined;
          },
        );
      }
    });
  });

  // =========================================================================
  // Sanity: repo scoping is enforced at handler/service level
  // =========================================================================

  describe('Sanity: user ID used for queries always comes from auth context', () => {
    it('getSubscriptionStatus uses userId from authContext, not from request params or body', async () => {
      mockSubscriptionRepo.findSubscriptionByProviderId.mockClear();

      // Even if a physician tries to provide a different user ID in query params,
      // the handler uses authContext.userId
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/subscriptions/current?userId=${PHYSICIAN2_USER_ID}`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);

      // Verify the repo was called with physician1's ID (from auth context),
      // NOT physician2's ID (from the query parameter)
      expect(
        mockSubscriptionRepo.findSubscriptionByProviderId,
      ).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
      expect(
        mockSubscriptionRepo.findSubscriptionByProviderId,
      ).not.toHaveBeenCalledWith(PHYSICIAN2_USER_ID);
    });

    it('payment history uses authenticated user subscription, ignoring injected subscription IDs', async () => {
      mockSubscriptionRepo.findSubscriptionByProviderId.mockClear();
      mockPaymentRepo.listPaymentsForSubscription.mockClear();

      // Physician1 tries to inject physician2's subscription ID
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/subscriptions/payments?subscriptionId=${SUBSCRIPTION2_ID}`,
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);

      // Verify the subscription lookup used physician1's user ID
      expect(
        mockSubscriptionRepo.findSubscriptionByProviderId,
      ).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);

      // Verify payment listing used physician1's subscription ID, not physician2's
      expect(
        mockPaymentRepo.listPaymentsForSubscription,
      ).toHaveBeenCalledWith(SUBSCRIPTION1_ID, expect.any(Object));
      expect(
        mockPaymentRepo.listPaymentsForSubscription,
      ).not.toHaveBeenCalledWith(SUBSCRIPTION2_ID, expect.any(Object));
    });
  });
});
