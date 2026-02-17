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

// Expired session (revoked)
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);

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
      constructEvent: vi.fn((payload, signature, secret) => {
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
      // Expired session token — returns undefined (simulates revoked/expired)
      // Tampered tokens — also returns undefined (no matching session)
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
// Helpers
// ---------------------------------------------------------------------------

/** Generates a tampered cookie (valid-looking hex but won't match any session). */
function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Authenticated routes to test — 1 entry per protected platform endpoint
// ---------------------------------------------------------------------------

const SUBSCRIPTION_ID = '00000000-3333-0000-0000-000000000001';
const INCIDENT_ID = '00000000-5555-0000-0000-000000000001';
const COMPONENT_ID = '00000000-4444-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/subscriptions/checkout',
    payload: {
      plan: 'STANDARD_MONTHLY',
      success_url: 'https://meritum.ca/success',
      cancel_url: 'https://meritum.ca/cancel',
    },
    description: 'Create checkout session',
  },
  {
    method: 'POST',
    url: '/api/v1/subscriptions/portal',
    payload: { return_url: 'https://meritum.ca/settings' },
    description: 'Create billing portal session',
  },
  {
    method: 'GET',
    url: '/api/v1/subscriptions/current',
    description: 'Get current subscription',
  },
  {
    method: 'GET',
    url: '/api/v1/subscriptions/payments',
    description: 'Get payment history',
  },
  {
    method: 'GET',
    url: '/api/v1/admin/subscriptions',
    description: 'List all subscriptions (admin)',
  },
  {
    method: 'PATCH',
    url: `/api/v1/admin/subscriptions/${SUBSCRIPTION_ID}/status`,
    payload: { status: 'SUSPENDED' },
    description: 'Update subscription status (admin)',
  },
  {
    method: 'POST',
    url: '/api/v1/admin/incidents',
    payload: {
      title: 'Test Incident',
      severity: 'minor',
      affected_components: [COMPONENT_ID],
      message: 'Test message.',
    },
    description: 'Create incident (admin)',
  },
  {
    method: 'POST',
    url: `/api/v1/admin/incidents/${INCIDENT_ID}/updates`,
    payload: { status: 'identified', message: 'Root cause found.' },
    description: 'Post incident update (admin)',
  },
  {
    method: 'PATCH',
    url: `/api/v1/admin/components/${COMPONENT_ID}/status`,
    payload: { status: 'maintenance' },
    description: 'Update component status (admin)',
  },
];

// ---------------------------------------------------------------------------
// Public routes to verify — must NOT require auth
// ---------------------------------------------------------------------------

interface PublicRouteSpec {
  method: 'GET' | 'POST';
  url: string;
  description: string;
  expectedNotStatus?: number;
  payload?: Record<string, unknown>;
  headers?: Record<string, string>;
}

const PUBLIC_ROUTES: PublicRouteSpec[] = [
  {
    method: 'GET',
    url: '/api/v1/status',
    description: 'Status page',
  },
  {
    method: 'GET',
    url: '/api/v1/status/incidents',
    description: 'Incident history',
  },
  {
    method: 'GET',
    url: `/api/v1/status/incidents/${randomUUID()}`,
    description: 'Incident detail (may 404 but never 401)',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Platform Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // No Cookie — each protected route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 without session cookie (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        // No data leakage — must not contain data field
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired Cookie — each protected route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with expired session (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Tampered Cookie — each protected route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with tampered cookie (${route.description})`, async () => {
        const tamperedToken = createTamperedCookie();
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${tamperedToken}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Empty cookie value — returns 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with empty cookie value (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: 'session=' },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Wrong cookie name — returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `token=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `auth=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak information
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/payments',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('stripe');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/subscriptions/checkout',
        payload: {
          plan: 'STANDARD_MONTHLY',
          success_url: 'https://meritum.ca/success',
          cancel_url: 'https://meritum.ca/cancel',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      // Should only have code and message — no extra fields
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });

  // =========================================================================
  // Public routes DO NOT require auth — must return non-401
  // =========================================================================

  describe('Public routes are accessible without authentication', () => {
    for (const route of PUBLIC_ROUTES) {
      it(`${route.method} ${route.url} — does not return 401 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
        });

        // Public routes must never return 401
        expect(res.statusCode).not.toBe(401);
        // They should return 200 or 404 (for non-existent incident ID), not 403
        expect([200, 404]).toContain(res.statusCode);
      });
    }

    it('GET /api/v1/status returns 200 without cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('GET /api/v1/status/incidents returns 200 without cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.pagination).toBeDefined();
    });
  });

  // =========================================================================
  // Stripe webhook does NOT return 401 — uses signature verification
  // =========================================================================

  describe('Stripe webhook uses signature verification, not session auth', () => {
    it('POST /api/v1/webhooks/stripe does not return 401 without session cookie', async () => {
      const event = {
        id: 'evt_test_authn',
        type: 'checkout.session.completed',
        data: {
          object: {
            metadata: {
              meritum_user_id: PHYSICIAN_USER_ID,
              plan: 'STANDARD_MONTHLY',
            },
            customer: 'cus_test_12345',
            subscription: 'sub_test_12345',
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

      // Must NOT be 401 — webhook has its own auth mechanism (signature)
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/webhooks/stripe with invalid signature returns 400 (not 401)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: { id: 'evt_bad', type: 'test', data: { object: {} } },
        headers: {
          'stripe-signature': 'invalid_signature',
          'content-type': 'application/json',
        },
      });

      // Must be 400 (bad signature), NOT 401 (which would mean session auth)
      expect(res.statusCode).toBe(400);
    });

    it('POST /api/v1/webhooks/stripe without signature header returns 400 (not 401)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/webhooks/stripe',
        payload: { id: 'evt_nosig', type: 'test', data: { object: {} } },
        headers: {
          'content-type': 'application/json',
        },
      });

      expect(res.statusCode).toBe(400);
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (confirms test setup)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/subscriptions/current returns non-401 with valid physician session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/subscriptions/current',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/admin/subscriptions returns non-401 with valid admin session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/subscriptions',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/admin/incidents returns non-401 with valid admin session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          title: 'Sanity Check',
          severity: 'minor',
          affected_components: [COMPONENT_ID],
          message: 'Testing auth acceptance.',
        },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });
});
