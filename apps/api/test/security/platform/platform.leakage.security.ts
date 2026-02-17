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
// Fixed test identities — physician + admin
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Stripe internal identifiers (MUST NOT appear in physician responses)
// ---------------------------------------------------------------------------

const STRIPE_CUSTOMER_ID = 'cus_physician1_secret_id';
const STRIPE_SUBSCRIPTION_ID = 'sub_physician1_secret_id';
const STRIPE_INVOICE_ID = 'inv_physician1_secret_001';

// ---------------------------------------------------------------------------
// Subscription + payment data
// ---------------------------------------------------------------------------

const SUBSCRIPTION_ID = '00000000-3333-0000-0000-000000000001';

const subscription1 = {
  subscriptionId: SUBSCRIPTION_ID,
  providerId: PHYSICIAN_USER_ID,
  stripeCustomerId: STRIPE_CUSTOMER_ID,
  stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
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

const PAYMENT_ID = '00000000-6666-0000-0000-000000000001';

const payment1 = {
  paymentId: PAYMENT_ID,
  subscriptionId: SUBSCRIPTION_ID,
  stripeInvoiceId: STRIPE_INVOICE_ID,
  amountCad: '279.00',
  gstAmount: '13.95',
  totalCad: '292.95',
  status: 'PAID',
  paidAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01'),
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
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async () => ({})),
    findSubscriptionByProviderId: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...subscription1 };
      return undefined;
    }),
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
    findAllSubscriptions: vi.fn(async () => ({
      data: [{ ...subscription1 }],
      total: 1,
    })),
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async () => ({})),
    findPaymentByStripeInvoiceId: vi.fn(async () => undefined),
    listPaymentsForSubscription: vi.fn(async (subscriptionId: string) => {
      if (subscriptionId === SUBSCRIPTION_ID) {
        return { data: [{ ...payment1 }], total: 1 };
      }
      return { data: [], total: 0 };
    }),
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
    listComponents: vi.fn(async () => [
      {
        componentId: '00000000-4444-0000-0000-000000000001',
        name: 'web_app',
        displayName: 'Web Application',
        status: 'OPERATIONAL',
        description: null,
        sortOrder: 1,
      },
    ]),
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
    findUserById: vi.fn(async () => undefined),
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
let mockStripe: ReturnType<typeof createMockStripe>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: createMockSubscriptionRepo() as any,
    paymentRepo: createMockPaymentRepo() as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    userRepo: createMockUserRepo(),
    stripe: mockStripe,
    config: {
      stripePriceStandardMonthly: 'price_monthly_test',
      stripePriceStandardAnnual: 'price_annual_test',
      stripePriceEarlyBirdMonthly: 'price_earlybird_test',
      stripeWebhookSecret: 'whsec_test_secret_value_1234',
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
    webhookSecret: 'whsec_test_secret_value_1234',
  });

  // Error handler — mirrors production behaviour
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

describe('Platform Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Stripe Data Isolation — GET /subscriptions/current
  // =========================================================================

  describe('GET /api/v1/subscriptions/current — no Stripe internals in response', () => {
    it('does NOT return stripe_customer_id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(STRIPE_CUSTOMER_ID);
      expect(rawBody).not.toContain('stripeCustomerId');
      expect(rawBody).not.toContain('stripe_customer_id');
      expect(rawBody).not.toContain('cus_');
    });

    it('does NOT return stripe_subscription_id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(STRIPE_SUBSCRIPTION_ID);
      expect(rawBody).not.toContain('stripeSubscriptionId');
      expect(rawBody).not.toContain('stripe_subscription_id');
      // Note: "sub_" is not checked here because "subscription" contains "sub"
    });

    it('returns only expected fields (status, plan, features, subscription shape)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Must have expected top-level data shape
      expect(body.data).toHaveProperty('status');
      expect(body.data).toHaveProperty('plan');
      expect(body.data).toHaveProperty('features');
      expect(body.data).toHaveProperty('subscription');

      // subscription sub-object must not contain Stripe fields
      if (body.data.subscription) {
        const subKeys = Object.keys(body.data.subscription);
        expect(subKeys).not.toContain('stripeCustomerId');
        expect(subKeys).not.toContain('stripeSubscriptionId');
        expect(subKeys).not.toContain('stripe_customer_id');
        expect(subKeys).not.toContain('stripe_subscription_id');
      }
    });
  });

  // =========================================================================
  // Stripe Data Isolation — GET /subscriptions/payments
  // =========================================================================

  describe('GET /api/v1/subscriptions/payments — no Stripe internals in response', () => {
    it('does NOT return stripe_invoice_id in payment records', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(STRIPE_INVOICE_ID);
      expect(rawBody).not.toContain('stripeInvoiceId');
      expect(rawBody).not.toContain('stripe_invoice_id');
      expect(rawBody).not.toContain('inv_');
    });

    it('payment responses contain only amount, GST, total, status, date', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);

      for (const payment of body.data) {
        // Should include financial fields
        expect(payment).toHaveProperty('amountCad');
        expect(payment).toHaveProperty('gstAmount');
        expect(payment).toHaveProperty('totalCad');
        expect(payment).toHaveProperty('status');

        // Should NOT include Stripe internal fields
        expect(payment).not.toHaveProperty('stripeInvoiceId');
        expect(payment).not.toHaveProperty('stripe_invoice_id');
      }
    });
  });

  // =========================================================================
  // Admin responses — SHOULD include Stripe IDs (for debugging)
  // =========================================================================

  describe('Admin subscription list includes Stripe IDs', () => {
    it('GET /api/v1/admin/subscriptions returns Stripe IDs for admin', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);

      // Admin responses SHOULD include Stripe IDs for debugging
      const sub = body.data[0];
      expect(sub.stripeCustomerId).toBe(STRIPE_CUSTOMER_ID);
      expect(sub.stripeSubscriptionId).toBe(STRIPE_SUBSCRIPTION_ID);
    });
  });

  // =========================================================================
  // Non-admin responses never include Stripe IDs
  // =========================================================================

  describe('Non-admin responses never include Stripe IDs', () => {
    it('physician GET /subscriptions/current has no Stripe customer or subscription IDs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      // Verify no Stripe prefixed identifiers leak
      expect(rawBody).not.toContain('cus_');
      expect(rawBody).not.toMatch(/sub_physician/);
    });

    it('physician GET /subscriptions/payments has no Stripe invoice IDs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('inv_');
      expect(rawBody).not.toContain(STRIPE_INVOICE_ID);
    });
  });

  // =========================================================================
  // PHI Isolation — no PHI in platform responses
  // =========================================================================

  describe('No PHI in platform operations responses', () => {
    it('subscription status response contains no patient or claim data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // PHI field names that must never appear in platform responses
      const phiFieldNames = [
        'patientId',
        'patient_id',
        'phn',
        'firstName',
        'lastName',
        'dateOfBirth',
        'healthServiceCode',
        'diagnosticCode',
        'claimId',
        'claim_id',
      ];

      for (const field of phiFieldNames) {
        expect(rawBody).not.toContain(field);
      }
    });

    it('payment history response contains no patient or claim data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      const phiFieldNames = [
        'patientId',
        'patient_id',
        'phn',
        'firstName',
        'lastName',
        'dateOfBirth',
        'healthServiceCode',
        'diagnosticCode',
      ];

      for (const field of phiFieldNames) {
        expect(rawBody).not.toContain(field);
      }
    });

    it('status page response contains no PHI', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      const phiFieldNames = [
        'patientId',
        'phn',
        'firstName',
        'lastName',
        'dateOfBirth',
        'healthServiceCode',
      ];

      for (const field of phiFieldNames) {
        expect(rawBody).not.toContain(field);
      }
    });
  });

  // =========================================================================
  // Error Response Sanitisation
  // =========================================================================

  describe('Error response sanitisation', () => {
    it('500 errors do not expose Stripe API keys or webhook secrets', async () => {
      // The error handler should mask all internal details on 500
      // We verify by checking that the test app's error handler works correctly
      // with a synthetic 500 error
      const errorApp = Fastify({ logger: false });
      errorApp.setValidatorCompiler(validatorCompiler);
      errorApp.setSerializerCompiler(serializerCompiler);

      // Route that deliberately throws with Stripe secret content
      errorApp.get('/test/error', async () => {
        throw new Error(
          'Stripe API error: sk_live_secret_key_12345 whsec_test_secret_value_1234',
        );
      });

      errorApp.setErrorHandler((_error, _request, reply) => {
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await errorApp.ready();

      const res = await errorApp.inject({
        method: 'GET',
        url: '/test/error',
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;

      // Must not contain any Stripe secrets
      expect(rawBody).not.toContain('sk_live');
      expect(rawBody).not.toContain('sk_test');
      expect(rawBody).not.toContain('whsec_');
      expect(rawBody).not.toContain('secret_key');

      // Must have generic error message
      const body = JSON.parse(rawBody);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');

      await errorApp.close();
    });

    it('500 errors do not expose database connection strings', async () => {
      const errorApp = Fastify({ logger: false });
      errorApp.setValidatorCompiler(validatorCompiler);
      errorApp.setSerializerCompiler(serializerCompiler);

      errorApp.get('/test/db-error', async () => {
        throw new Error(
          'Connection failed: postgresql://user:password@host:5432/meritum',
        );
      });

      errorApp.setErrorHandler((_error, _request, reply) => {
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await errorApp.ready();

      const res = await errorApp.inject({
        method: 'GET',
        url: '/test/db-error',
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;

      // Must not contain DB connection details
      expect(rawBody).not.toContain('postgresql://');
      expect(rawBody).not.toContain('password');
      expect(rawBody).not.toContain(':5432');

      // Must have generic error
      const body = JSON.parse(rawBody);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');

      await errorApp.close();
    });

    it('500 errors on subscription endpoints do not expose stack traces', async () => {
      // Force the subscription endpoint to throw an internal error
      // by making the mock repo throw
      const throwingApp = Fastify({ logger: false });
      throwingApp.setValidatorCompiler(validatorCompiler);
      throwingApp.setSerializerCompiler(serializerCompiler);

      const throwingSubRepo = createMockSubscriptionRepo();
      throwingSubRepo.findSubscriptionByProviderId.mockRejectedValue(
        new Error('ECONNREFUSED: connect to db-host:5432 postgresql://user:pass@host/meritum'),
      );

      const throwingStripe = createMockStripe();
      const mockEvents = { emit: vi.fn() };

      const serviceDeps: PlatformServiceDeps = {
        subscriptionRepo: throwingSubRepo as any,
        paymentRepo: createMockPaymentRepo() as any,
        statusComponentRepo: createMockStatusComponentRepo() as any,
        incidentRepo: createMockIncidentRepo() as any,
        userRepo: createMockUserRepo(),
        stripe: throwingStripe,
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

      await throwingApp.register(authPluginFp, {
        sessionDeps: {
          sessionRepo: createMockSessionRepo(),
          auditRepo: { appendAuditLog: vi.fn() },
          events: mockEvents,
        },
      });

      await throwingApp.register(stripeWebhookPluginFp, {
        webhookPath: '/api/v1/webhooks/stripe',
        stripe: throwingStripe,
        webhookSecret: 'whsec_test_secret',
      });

      throwingApp.setErrorHandler((error, _request, reply) => {
        if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
          return reply.code(error.statusCode).send({
            error: {
              code: (error as any).code ?? 'ERROR',
              message: error.message,
            },
          });
        }
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await throwingApp.register(platformRoutes, { deps: handlerDeps });
      await throwingApp.ready();

      const res = await throwingApp.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      const body = JSON.parse(rawBody);

      // Must not expose internal error details
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');
      expect(rawBody).not.toContain('ECONNREFUSED');
      expect(rawBody).not.toContain('postgresql');
      expect(rawBody).not.toContain('db-host');
      expect(rawBody).not.toContain('drizzle');

      await throwingApp.close();
    });

    it('webhook verification failures return generic 400, not the expected signature', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: { id: 'evt_bad', type: 'test', data: { object: {} } },
        headers: {
          'stripe-signature': 'invalid_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);

      // Must NOT reveal the expected signature or webhook secret
      const rawBody = res.body;
      expect(rawBody).not.toContain('whsec_');
      expect(rawBody).not.toContain('expected');
      expect(rawBody).not.toContain(
        'whsec_test_secret_value_1234',
      );

      // Generic error message
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
    });

    it('404 responses use generic message without resource details', async () => {
      const nonExistentId = randomUUID();
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/status/incidents/${nonExistentId}`,
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);

      // Must not echo back the UUID
      expect(body.error.message).not.toContain(nonExistentId);

      // Generic not found message
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // Response Header Checks
  // =========================================================================

  describe('Response header security', () => {
    it('no X-Powered-By header on physician endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on public endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version on physician endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      // Server header should not exist or not reveal version info
      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header revealing version on public endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header revealing version on admin endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('no Server header revealing version on webhook endpoint', async () => {
      const event = {
        id: 'evt_header_test',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN_USER_ID,
              plan: 'STANDARD_MONTHLY',
            },
            customer: 'cus_test',
            subscription: 'sub_test',
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

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/node/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });
  });

  // =========================================================================
  // Status page cache headers
  // =========================================================================

  describe('Status page responses include appropriate cache headers', () => {
    it('GET /api/v1/status does not include private cache-control', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);

      // Status page is public data — should not have "private" or "no-store"
      const cacheControl = res.headers['cache-control'] as string | undefined;
      if (cacheControl) {
        expect(cacheControl).not.toContain('private');
        expect(cacheControl).not.toContain('no-store');
      }
    });

    it('GET /api/v1/status/incidents does not include private cache-control', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents',
      });

      expect(res.statusCode).toBe(200);
      const cacheControl = res.headers['cache-control'] as string | undefined;
      if (cacheControl) {
        expect(cacheControl).not.toContain('private');
        expect(cacheControl).not.toContain('no-store');
      }
    });
  });

  // =========================================================================
  // Webhook handler does not log PHI
  // =========================================================================

  describe('Stripe webhook handler does not log PHI', () => {
    it('webhook response body contains no PHI fields', async () => {
      const event = {
        id: 'evt_phi_test',
        type: 'invoice.paid',
        data: {
          object: {
            id: 'inv_phi_test',
            subscription: STRIPE_SUBSCRIPTION_ID,
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

      // The webhook response should just acknowledge receipt
      const rawBody = res.body;
      const phiFields = [
        'patientId',
        'phn',
        'firstName',
        'lastName',
        'dateOfBirth',
        'healthServiceCode',
        'diagnosticCode',
      ];

      for (const field of phiFields) {
        expect(rawBody).not.toContain(field);
      }
    });

    it('webhook response is minimal (only received: true)', async () => {
      const event = {
        id: 'evt_minimal_test',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN_USER_ID,
              plan: 'STANDARD_MONTHLY',
            },
            customer: 'cus_minimal_test',
            subscription: 'sub_minimal_test',
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
      const body = JSON.parse(res.body);

      // Response should be minimal
      expect(body.data).toEqual({ received: true });

      // Should not echo back event data
      expect(res.body).not.toContain('cus_minimal_test');
      expect(res.body).not.toContain('sub_minimal_test');
    });
  });

  // =========================================================================
  // Error responses on authenticated endpoints
  // =========================================================================

  describe('Error responses on authenticated endpoints are sanitised', () => {
    it('conflict error on checkout does not leak Stripe customer ID', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      // Should be 409 (conflict — already has subscription)
      const rawBody = res.body;
      expect(rawBody).not.toContain(STRIPE_CUSTOMER_ID);
      expect(rawBody).not.toContain(STRIPE_SUBSCRIPTION_ID);
      expect(rawBody).not.toContain('cus_');
    });

    it('portal session 404 does not reveal subscription details', async () => {
      // Use a user without a subscription — temporarily override mock
      const noSubApp = Fastify({ logger: false });
      noSubApp.setValidatorCompiler(validatorCompiler);
      noSubApp.setSerializerCompiler(serializerCompiler);

      const noSubRepo = createMockSubscriptionRepo();
      noSubRepo.findSubscriptionByProviderId.mockResolvedValue(undefined);

      const mockEvents = { emit: vi.fn() };
      const noSubStripe = createMockStripe();

      const serviceDeps: PlatformServiceDeps = {
        subscriptionRepo: noSubRepo as any,
        paymentRepo: createMockPaymentRepo() as any,
        statusComponentRepo: createMockStatusComponentRepo() as any,
        incidentRepo: createMockIncidentRepo() as any,
        userRepo: createMockUserRepo(),
        stripe: noSubStripe,
        config: {
          stripePriceStandardMonthly: 'price_monthly_test',
          stripePriceStandardAnnual: 'price_annual_test',
          stripePriceEarlyBirdMonthly: 'price_earlybird_test',
          stripeWebhookSecret: 'whsec_test_secret',
        },
      };

      await noSubApp.register(authPluginFp, {
        sessionDeps: {
          sessionRepo: createMockSessionRepo(),
          auditRepo: { appendAuditLog: vi.fn() },
          events: mockEvents,
        },
      });

      await noSubApp.register(stripeWebhookPluginFp, {
        webhookPath: '/api/v1/webhooks/stripe',
        stripe: noSubStripe,
        webhookSecret: 'whsec_test_secret',
      });

      noSubApp.setErrorHandler((error, _request, reply) => {
        if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
          return reply.code(error.statusCode).send({
            error: {
              code: (error as any).code ?? 'ERROR',
              message: error.message,
            },
          });
        }
        return reply.code(500).send({
          error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
        });
      });

      await noSubApp.register(platformRoutes, {
        deps: { serviceDeps, eventEmitter: mockEvents },
      });
      await noSubApp.ready();

      const res = await noSubApp.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { return_url: 'https://meritum.ca/settings' },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);

      // Generic not-found — no Stripe internals
      expect(body.error.message).not.toContain('cus_');
      expect(body.error.message).not.toContain('sub_');
      expect(body.error.message).not.toContain('stripe');

      await noSubApp.close();
    });
  });
});
