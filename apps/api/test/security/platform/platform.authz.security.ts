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

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician — ACTIVE subscription
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

// Admin
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000000099';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000000099';

// Delegate (linked to physician1)
const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

// Suspended physician — SUSPENDED subscription
const SUSPENDED_USER_ID = '00000000-1111-0000-0000-000000000070';
const SUSPENDED_SESSION_TOKEN = randomBytes(32).toString('hex');
const SUSPENDED_SESSION_TOKEN_HASH = hashToken(SUSPENDED_SESSION_TOKEN);
const SUSPENDED_SESSION_ID = '00000000-2222-0000-0000-000000000070';

// Cancelled physician — CANCELLED subscription
const CANCELLED_USER_ID = '00000000-1111-0000-0000-000000000080';
const CANCELLED_SESSION_TOKEN = randomBytes(32).toString('hex');
const CANCELLED_SESSION_TOKEN_HASH = hashToken(CANCELLED_SESSION_TOKEN);
const CANCELLED_SESSION_ID = '00000000-2222-0000-0000-000000000080';

// ---------------------------------------------------------------------------
// UUID constants for route params
// ---------------------------------------------------------------------------

const SUBSCRIPTION_ID = '00000000-3333-0000-0000-000000000001';
const INCIDENT_ID = '00000000-5555-0000-0000-000000000001';
const COMPONENT_ID = '00000000-4444-0000-0000-000000000001';

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
    findUserById: vi.fn(async () => undefined),
    updateSubscriptionStatus: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock session repository — supports physician, admin, delegate,
// suspended, and cancelled user sessions
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      // Active physician
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

      // Delegate (limited permissions, linked to physician)
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

      // Suspended physician
      if (tokenHash === SUSPENDED_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: SUSPENDED_SESSION_ID,
            userId: SUSPENDED_USER_ID,
            tokenHash: SUSPENDED_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: SUSPENDED_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'SUSPENDED',
          },
        };
      }

      // Cancelled physician
      if (tokenHash === CANCELLED_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: CANCELLED_SESSION_ID,
            userId: CANCELLED_USER_ID,
            tokenHash: CANCELLED_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: CANCELLED_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'CANCELLED',
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

  // Error handler (consistent with authn security tests)
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

describe('Platform Authorization & Role Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Category A: Delegate cannot access subscription management
  // =========================================================================

  describe('Delegate cannot access subscription management', () => {
    it('POST /api/v1/subscriptions/checkout — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/subscriptions/portal — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/portal',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: { return_url: 'https://meritum.ca/settings' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/subscriptions/current — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/subscriptions/payments — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Category B: Delegate cannot access admin routes
  // =========================================================================

  describe('Delegate cannot access admin routes', () => {
    it('GET /api/v1/admin/subscriptions — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('PATCH /api/v1/admin/subscriptions/:id/status — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: { status: 'SUSPENDED' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /api/v1/admin/incidents — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          title: 'Test Incident',
          severity: 'minor',
          affected_components: [COMPONENT_ID],
          message: 'Test message.',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /api/v1/admin/incidents/:id/updates — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${INCIDENT_ID}/updates`,
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: { status: 'identified', message: 'Root cause found.' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('PATCH /api/v1/admin/components/:id/status — delegate receives 403', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_ID}/status`,
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: { status: 'maintenance' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // Category C: Non-admin (physician) cannot access admin routes
  // =========================================================================

  describe('Physician (non-admin) cannot access admin routes', () => {
    it('GET /api/v1/admin/subscriptions — physician receives 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PATCH /api/v1/admin/subscriptions/:id/status — physician receives 403', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { status: 'SUSPENDED' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/admin/incidents — physician receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          title: 'Unauthorized Incident',
          severity: 'critical',
          affected_components: [COMPONENT_ID],
          message: 'Should be rejected.',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/admin/incidents/:id/updates — physician receives 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${INCIDENT_ID}/updates`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { status: 'identified', message: 'Should not work.' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PATCH /api/v1/admin/components/:id/status — physician receives 403', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_ID}/status`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { status: 'maintenance' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Category D: Admin CAN access admin routes (sanity check)
  // =========================================================================

  describe('Admin can access admin routes (sanity)', () => {
    it('GET /api/v1/admin/subscriptions — admin receives non-403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/admin/incidents — admin receives non-403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          title: 'Admin Incident',
          severity: 'minor',
          affected_components: [COMPONENT_ID],
          message: 'Admin should be allowed.',
        },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PATCH /api/v1/admin/components/:id/status — admin receives non-403', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_ID}/status`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: { status: 'maintenance' },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Category E: Physician CAN access subscription routes (sanity check)
  // =========================================================================

  describe('Physician can access subscription routes (sanity)', () => {
    it('GET /api/v1/subscriptions/current — physician receives non-403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/subscriptions/payments — physician receives non-403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Category F: 403 response body does not leak internal details
  // =========================================================================

  describe('403 responses do not leak internal details', () => {
    it('delegate 403 on subscription checkout — no stack or internals', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('stripe');
    });

    it('physician 403 on admin route — no stack or internals', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('403 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          title: 'Test',
          severity: 'minor',
          affected_components: [COMPONENT_ID],
          message: 'Test.',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });

  // =========================================================================
  // Category G: Subscription-gated access — SUSPENDED user
  // =========================================================================

  describe('Subscription-gated access — SUSPENDED physician', () => {
    it('SUSPENDED physician — subscription checkout still accessible (to reactivate)', async () => {
      // Checkout and portal should still work so the user can fix billing.
      // The subscription routes require PHYSICIAN role, not subscription status.
      // But feature-gated endpoints behind checkSubscription would block.
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${SUSPENDED_SESSION_TOKEN}` },
      });

      // Subscription management routes themselves don't enforce checkSubscription,
      // so they should succeed. The user needs these to resolve their suspension.
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('SUSPENDED physician — checkSubscription middleware blocks feature access with 402', async () => {
      // Verify the checkSubscription decorator correctly blocks SUSPENDED status.
      // We call it directly since platform routes don't use checkSubscription
      // (it's applied on feature domains like claims), but we can verify the
      // middleware's behavior by injecting a request through a test route.

      // Build a mini app with a checkSubscription-guarded route
      const miniApp = Fastify({ logger: false });
      miniApp.setValidatorCompiler(validatorCompiler);
      miniApp.setSerializerCompiler(serializerCompiler);

      await miniApp.register(authPluginFp, {
        sessionDeps: {
          sessionRepo: createMockSessionRepo(),
          auditRepo: { appendAuditLog: vi.fn() },
          events: { emit: vi.fn() },
        },
      });

      miniApp.setErrorHandler((error, request, reply) => {
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

      // Simulate a claims-like endpoint guarded by checkSubscription
      miniApp.post('/api/v1/test/create-claim', {
        preHandler: [
          miniApp.authenticate,
          miniApp.checkSubscription('ACTIVE', 'TRIAL'),
        ],
        handler: async (_request, reply) => {
          return reply.code(201).send({ data: { id: 'claim_123' } });
        },
      });

      await miniApp.ready();

      try {
        // Active physician can create claims
        const activeRes = await miniApp.inject({
          method: 'POST',
          url: '/api/v1/test/create-claim',
          headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        });
        expect(activeRes.statusCode).toBe(201);

        // Suspended physician is blocked with 402
        const suspendedRes = await miniApp.inject({
          method: 'POST',
          url: '/api/v1/test/create-claim',
          headers: { cookie: `session=${SUSPENDED_SESSION_TOKEN}` },
        });
        expect(suspendedRes.statusCode).toBe(402);
        const body = JSON.parse(suspendedRes.body);
        expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
      } finally {
        await miniApp.close();
      }
    });
  });

  // =========================================================================
  // Category H: Subscription-gated access — CANCELLED user
  // =========================================================================

  describe('Subscription-gated access — CANCELLED physician', () => {
    it('CANCELLED physician — checkSubscription blocks feature access with 402', async () => {
      const miniApp = Fastify({ logger: false });
      miniApp.setValidatorCompiler(validatorCompiler);
      miniApp.setSerializerCompiler(serializerCompiler);

      await miniApp.register(authPluginFp, {
        sessionDeps: {
          sessionRepo: createMockSessionRepo(),
          auditRepo: { appendAuditLog: vi.fn() },
          events: { emit: vi.fn() },
        },
      });

      miniApp.setErrorHandler((error, request, reply) => {
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

      // Feature endpoint (claims creation)
      miniApp.post('/api/v1/test/create-claim', {
        preHandler: [
          miniApp.authenticate,
          miniApp.checkSubscription('ACTIVE', 'TRIAL'),
        ],
        handler: async (_request, reply) => {
          return reply.code(201).send({ data: { id: 'claim_123' } });
        },
      });

      // Data export endpoint — should be accessible even when cancelled
      miniApp.get('/api/v1/test/data-export', {
        preHandler: [
          miniApp.authenticate,
          miniApp.checkSubscription('ACTIVE', 'TRIAL', 'PAST_DUE', 'SUSPENDED', 'CANCELLED'),
        ],
        handler: async (_request, reply) => {
          return reply.code(200).send({ data: { export: 'allowed' } });
        },
      });

      await miniApp.ready();

      try {
        // Cancelled physician cannot create claims
        const claimRes = await miniApp.inject({
          method: 'POST',
          url: '/api/v1/test/create-claim',
          headers: { cookie: `session=${CANCELLED_SESSION_TOKEN}` },
        });
        expect(claimRes.statusCode).toBe(402);
        const body = JSON.parse(claimRes.body);
        expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');

        // Cancelled physician CAN access data export (all statuses allowed)
        const exportRes = await miniApp.inject({
          method: 'GET',
          url: '/api/v1/test/data-export',
          headers: { cookie: `session=${CANCELLED_SESSION_TOKEN}` },
        });
        expect(exportRes.statusCode).toBe(200);
        const exportBody = JSON.parse(exportRes.body);
        expect(exportBody.data).toBeDefined();
      } finally {
        await miniApp.close();
      }
    });

    it('CANCELLED physician — can still access subscription management (to re-subscribe)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${CANCELLED_SESSION_TOKEN}` },
      });

      // Subscription management routes don't enforce checkSubscription
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Category I: Subscription status 402 responses do not leak info
  // =========================================================================

  describe('402 responses do not leak internal details', () => {
    it('402 ACCOUNT_SUSPENDED — no stack traces or internals', async () => {
      const miniApp = Fastify({ logger: false });
      miniApp.setValidatorCompiler(validatorCompiler);
      miniApp.setSerializerCompiler(serializerCompiler);

      await miniApp.register(authPluginFp, {
        sessionDeps: {
          sessionRepo: createMockSessionRepo(),
          auditRepo: { appendAuditLog: vi.fn() },
          events: { emit: vi.fn() },
        },
      });

      miniApp.setErrorHandler((error, request, reply) => {
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

      miniApp.get('/api/v1/test/feature', {
        preHandler: [
          miniApp.authenticate,
          miniApp.checkSubscription('ACTIVE', 'TRIAL'),
        ],
        handler: async (_request, reply) => reply.send({ data: {} }),
      });

      await miniApp.ready();

      try {
        const res = await miniApp.inject({
          method: 'GET',
          url: '/api/v1/test/feature',
          headers: { cookie: `session=${SUSPENDED_SESSION_TOKEN}` },
        });

        expect(res.statusCode).toBe(402);
        const rawBody = res.body;
        expect(rawBody).not.toContain('stack');
        expect(rawBody).not.toContain('node_modules');
        expect(rawBody).not.toContain('.ts:');
        expect(rawBody).not.toContain('postgres');
        expect(rawBody).not.toContain('drizzle');
        expect(rawBody).not.toContain('stripe');

        const body = JSON.parse(rawBody);
        expect(Object.keys(body)).toEqual(['error']);
        expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
      } finally {
        await miniApp.close();
      }
    });
  });
});
