import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup
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
  type StripeEvent,
} from '../../../src/domains/platform/platform.service.js';
import { SubscriptionPlan } from '@meritum/shared/constants/platform.constants.js';
import { SubscriptionStatus } from '@meritum/shared/constants/iam.constants.js';

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

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000099';

const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

const SUBSCRIPTION_ID = '00000000-3333-0000-0000-000000000001';
const STRIPE_CUSTOMER_ID = 'cus_test_12345';
const STRIPE_SUBSCRIPTION_ID = 'sub_test_12345';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockSubscriptions: Array<Record<string, any>>;
let mockPayments: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Stripe client
// ---------------------------------------------------------------------------

function createMockStripe(): StripeClient {
  return {
    customers: {
      create: vi.fn(async (params) => ({
        id: STRIPE_CUSTOMER_ID,
      })),
      del: vi.fn(async () => ({ id: STRIPE_CUSTOMER_ID, deleted: true })),
    },
    checkout: {
      sessions: {
        create: vi.fn(async (params) => ({
          url: 'https://checkout.stripe.com/test_session_url',
        })),
      },
    },
    billingPortal: {
      sessions: {
        create: vi.fn(async (params) => ({
          url: 'https://billing.stripe.com/test_portal_url',
        })),
      },
    },
    taxRates: {
      create: vi.fn(async () => ({ id: 'txr_test_123' })),
    },
    webhooks: {
      constructEvent: vi.fn((payload, signature, secret): StripeEvent => {
        if (signature === 'invalid_signature') {
          throw new Error('Invalid signature');
        }
        // Parse the raw body to return it as an event
        const parsed = JSON.parse(payload);
        return parsed as StripeEvent;
      }),
    },
    invoiceItems: {
      create: vi.fn(async () => ({ id: 'ii_test_123' })),
    },
    subscriptions: {
      cancel: vi.fn(async () => ({ id: STRIPE_SUBSCRIPTION_ID, status: 'canceled' })),
    },
  };
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSubscriptionRepo() {
  return {
    createSubscription: vi.fn(async (data: any) => {
      const sub = {
        subscriptionId: SUBSCRIPTION_ID,
        providerId: data.providerId,
        stripeCustomerId: data.stripeCustomerId,
        stripeSubscriptionId: data.stripeSubscriptionId,
        plan: data.plan,
        status: data.status,
        currentPeriodStart: data.currentPeriodStart ?? new Date(),
        currentPeriodEnd: data.currentPeriodEnd ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockSubscriptions.push(sub);
      return sub;
    }),
    findSubscriptionByProviderId: vi.fn(async (providerId: string) => {
      return mockSubscriptions.find((s) => s.providerId === providerId);
    }),
    findSubscriptionByStripeCustomerId: vi.fn(async (id: string) => {
      return mockSubscriptions.find((s) => s.stripeCustomerId === id);
    }),
    findSubscriptionByStripeSubscriptionId: vi.fn(async (id: string) => {
      return mockSubscriptions.find((s) => s.stripeSubscriptionId === id);
    }),
    updateSubscriptionStatus: vi.fn(async (subscriptionId: string, status: string, metadata?: any) => {
      const sub = mockSubscriptions.find((s) => s.subscriptionId === subscriptionId);
      if (!sub) return undefined;
      sub.status = status;
      sub.updatedAt = new Date();
      if (metadata?.suspended_at !== undefined) sub.suspendedAt = metadata.suspended_at;
      if (metadata?.cancelled_at !== undefined) sub.cancelledAt = metadata.cancelled_at;
      if (metadata?.deletion_scheduled_at !== undefined) sub.deletionScheduledAt = metadata.deletion_scheduled_at;
      return sub;
    }),
    updateSubscriptionPeriod: vi.fn(async (id: string, start: Date, end: Date) => {
      const sub = mockSubscriptions.find((s) => s.subscriptionId === id);
      if (!sub) return undefined;
      sub.currentPeriodStart = start;
      sub.currentPeriodEnd = end;
      return sub;
    }),
    updateSubscriptionPlan: vi.fn(async (id: string, plan: string) => {
      const sub = mockSubscriptions.find((s) => s.subscriptionId === id);
      if (!sub) return undefined;
      sub.plan = plan;
      return sub;
    }),
    incrementFailedPaymentCount: vi.fn(async (id: string) => {
      const sub = mockSubscriptions.find((s) => s.subscriptionId === id);
      if (!sub) return undefined;
      sub.failedPaymentCount++;
      return sub;
    }),
    resetFailedPaymentCount: vi.fn(async (id: string) => {
      const sub = mockSubscriptions.find((s) => s.subscriptionId === id);
      if (!sub) return undefined;
      sub.failedPaymentCount = 0;
      return sub;
    }),
    findPastDueSubscriptions: vi.fn(async () => {
      return mockSubscriptions.filter((s) => s.status === 'PAST_DUE');
    }),
    findSubscriptionsDueForSuspension: vi.fn(async () => []),
    findSubscriptionsDueForCancellation: vi.fn(async () => []),
    findSubscriptionsDueForDeletion: vi.fn(async () => []),
    countEarlyBirdSubscriptions: vi.fn(async () => 0),
    findAllSubscriptions: vi.fn(async (filters: { status?: string; page: number; pageSize: number }) => {
      let filtered = [...mockSubscriptions];
      if (filters.status) {
        filtered = filtered.filter((s) => s.status === filters.status);
      }
      const offset = (filters.page - 1) * filters.pageSize;
      return {
        data: filtered.slice(offset, offset + filters.pageSize),
        total: filtered.length,
      };
    }),
  };
}

function createMockPaymentRepo() {
  return {
    recordPayment: vi.fn(async (data: any) => {
      const payment = {
        paymentId: `pay-${mockPayments.length + 1}`,
        subscriptionId: data.subscriptionId,
        stripeInvoiceId: data.stripeInvoiceId,
        amountCad: data.amountCad,
        gstAmount: data.gstAmount,
        totalCad: data.totalCad,
        status: data.status,
        paidAt: data.paidAt,
        createdAt: new Date(),
      };
      mockPayments.push(payment);
      return payment;
    }),
    findPaymentByStripeInvoiceId: vi.fn(async (id: string) => {
      return mockPayments.find((p) => p.stripeInvoiceId === id);
    }),
    listPaymentsForSubscription: vi.fn(
      async (subscriptionId: string, pagination: { page: number; pageSize: number }) => {
        const filtered = mockPayments.filter((p) => p.subscriptionId === subscriptionId);
        const offset = (pagination.page - 1) * pagination.pageSize;
        return {
          data: filtered.slice(offset, offset + pagination.pageSize),
          total: filtered.length,
        };
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
      if (userId === PHYSICIAN_USER_ID) {
        return { userId: PHYSICIAN_USER_ID, email: 'dr@example.com', fullName: 'Dr. Test' };
      }
      if (userId === ADMIN_USER_ID) {
        return { userId: ADMIN_USER_ID, email: 'admin@meritum.ca', fullName: 'Admin User' };
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
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: DELEGATE_SESSION_ID,
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
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
let mockSubRepo: ReturnType<typeof createMockSubscriptionRepo>;
let mockPayRepo: ReturnType<typeof createMockPaymentRepo>;
let mockUserRepo: ReturnType<typeof createMockUserRepo>;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockStripe = createMockStripe();
  mockSubRepo = createMockSubscriptionRepo();
  mockPayRepo = createMockPaymentRepo();
  mockUserRepo = createMockUserRepo();
  mockSessionRepo = createMockSessionRepo();
  mockEvents = { emit: vi.fn() };

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: mockSubRepo as any,
    paymentRepo: mockPayRepo as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    userRepo: mockUserRepo,
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
    sessionDeps: { sessionRepo: mockSessionRepo, auditRepo: { appendAuditLog: vi.fn() }, events: mockEvents },
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

describe('Platform Subscriptions Integration Tests', () => {
  beforeAll(async () => {
    mockSubscriptions = [];
    mockPayments = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockSubscriptions = [];
    mockPayments = [];

    // Clear all mock call histories
    vi.clearAllMocks();
  });

  // =========================================================================
  // Stripe Webhook
  // =========================================================================

  describe('POST /api/v1/webhooks/stripe', () => {
    it('with valid signature processes event', async () => {
      const event: StripeEvent = {
        id: 'evt_test_123',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN_USER_ID,
              plan: SubscriptionPlan.STANDARD_MONTHLY,
            },
            customer: STRIPE_CUSTOMER_ID,
            subscription: STRIPE_SUBSCRIPTION_ID,
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
      expect(body.data.received).toBe(true);
    });

    it('with invalid signature returns 400', async () => {
      const event = {
        id: 'evt_test_bad',
        type: 'checkout.session.completed',
        data: { object: {} },
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: event,
        headers: {
          'stripe-signature': 'invalid_signature',
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
    });

    it('without stripe-signature header returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: { id: 'evt_test', type: 'test', data: { object: {} } },
        headers: {
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // POST /api/v1/subscriptions/checkout
  // =========================================================================

  describe('POST /api/v1/subscriptions/checkout', () => {
    it('returns checkout URL for authenticated physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          plan: SubscriptionPlan.STANDARD_MONTHLY,
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.checkout_url).toBe('https://checkout.stripe.com/test_session_url');
    });

    it('rejects delegate role', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
        payload: {
          plan: SubscriptionPlan.STANDARD_MONTHLY,
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        payload: {
          plan: SubscriptionPlan.STANDARD_MONTHLY,
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 with invalid plan', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          plan: 'INVALID_PLAN',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 with invalid URL', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          plan: SubscriptionPlan.STANDARD_MONTHLY,
          success_url: 'not-a-url',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 409 if user already has active subscription', async () => {
      // Seed an active subscription
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          plan: SubscriptionPlan.STANDARD_MONTHLY,
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(409);
    });
  });

  // =========================================================================
  // POST /api/v1/subscriptions/portal
  // =========================================================================

  describe('POST /api/v1/subscriptions/portal', () => {
    it('returns portal URL for active subscriber', async () => {
      // Seed subscription
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          return_url: 'https://meritum.ca/settings',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.portal_url).toBe('https://billing.stripe.com/test_portal_url');
    });

    it('returns 404 when no subscription exists', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          return_url: 'https://meritum.ca/settings',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        payload: {
          return_url: 'https://meritum.ca/settings',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects delegate role', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
        payload: {
          return_url: 'https://meritum.ca/settings',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 400 with invalid return_url', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          return_url: 'not-a-url',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/subscriptions/current
  // =========================================================================

  describe('GET /api/v1/subscriptions/current', () => {
    it('returns subscription for authenticated user', async () => {
      // Seed subscription
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe(SubscriptionStatus.ACTIVE);
      expect(body.data.plan).toBe(SubscriptionPlan.STANDARD_MONTHLY);
      expect(body.data.features).toBeDefined();
    });

    it('returns CANCELLED status when no subscription exists', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe(SubscriptionStatus.CANCELLED);
      expect(body.data.subscription).toBeNull();
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects delegate role', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // GET /api/v1/subscriptions/payments
  // =========================================================================

  describe('GET /api/v1/subscriptions/payments', () => {
    it('returns paginated payment history', async () => {
      // Seed subscription and payments
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      mockPayments.push({
        paymentId: 'pay-1',
        subscriptionId: SUBSCRIPTION_ID,
        stripeInvoiceId: 'in_test_001',
        amountCad: '265.71',
        gstAmount: '13.29',
        totalCad: '279.00',
        status: 'PAID',
        paidAt: new Date(),
        createdAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(1);
    });

    it('returns empty list when no subscription exists', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(0);
      expect(body.pagination.total).toBe(0);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects delegate role', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // GET /api/v1/admin/subscriptions
  // =========================================================================

  describe('GET /api/v1/admin/subscriptions', () => {
    it('returns all subscriptions for admin', async () => {
      // Seed subscriptions
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toBeDefined();
    });

    it('rejects non-admin (physician)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('rejects non-admin (delegate)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
      });

      expect(res.statusCode).toBe(401);
    });

    it('supports status filter', async () => {
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions?status=ACTIVE',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
    });
  });

  // =========================================================================
  // PATCH /api/v1/admin/subscriptions/:id/status
  // =========================================================================

  describe('PATCH /api/v1/admin/subscriptions/:id/status', () => {
    it('updates subscription status for admin', async () => {
      mockSubscriptions.push({
        subscriptionId: SUBSCRIPTION_ID,
        providerId: PHYSICIAN_USER_ID,
        stripeCustomerId: STRIPE_CUSTOMER_ID,
        stripeSubscriptionId: STRIPE_SUBSCRIPTION_ID,
        plan: SubscriptionPlan.STANDARD_MONTHLY,
        status: SubscriptionStatus.ACTIVE,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        failedPaymentCount: 0,
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: SubscriptionStatus.SUSPENDED,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe(SubscriptionStatus.SUSPENDED);
    });

    it('returns 404 for non-existent subscription', async () => {
      const fakeId = '99999999-0000-0000-0000-000000000099';
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${fakeId}/status`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: SubscriptionStatus.SUSPENDED,
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('rejects non-admin', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          status: SubscriptionStatus.SUSPENDED,
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
        payload: {
          status: SubscriptionStatus.SUSPENDED,
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 with non-UUID id', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/admin/subscriptions/not-a-uuid/status',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: SubscriptionStatus.SUSPENDED,
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });
});
