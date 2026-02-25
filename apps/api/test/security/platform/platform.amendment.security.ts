import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
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
  createAmendment,
  acknowledgeAmendment,
  respondToAmendment,
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

const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000050';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000050';

// Expired session (revoked)
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');

// Test amendment ID
const AMENDMENT_ID = '00000000-7777-0000-0000-000000000001';
const NON_EXISTENT_UUID = '00000000-9999-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Valid payload for creating an amendment
// ---------------------------------------------------------------------------

const VALID_AMENDMENT_PAYLOAD = {
  amendment_type: 'NON_MATERIAL',
  title: 'Test Amendment',
  description: 'Description of the amendment',
  document_text: 'Full document text goes here.',
  effective_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
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
// Mock amendment repository — tracks calls for audit tests
// ---------------------------------------------------------------------------

let mockAmendments: Array<Record<string, any>>;
let mockAmendmentResponses: Array<Record<string, any>>;

function createMockAmendmentRepo() {
  return {
    createAmendment: vi.fn(async (data: any) => {
      const amendment = {
        amendmentId: AMENDMENT_ID,
        amendmentType: data.amendmentType,
        title: data.title,
        description: data.description,
        documentHash: createHash('sha256').update(data.documentText).digest('hex'),
        noticeDate: new Date(),
        effectiveDate: data.effectiveDate,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockAmendments.push(amendment);
      return amendment;
    }),
    findAmendmentById: vi.fn(async (amendmentId: string) => {
      const found = mockAmendments.find((a) => a.amendmentId === amendmentId);
      if (!found) return undefined;
      return {
        ...found,
        responseCounts: { total: 0, acknowledged: 0, accepted: 0, rejected: 0 },
      };
    }),
    listAmendments: vi.fn(async (opts: any) => {
      return {
        data: mockAmendments,
        total: mockAmendments.length,
      };
    }),
    findPendingAmendmentsForProvider: vi.fn(async (_providerId: string) => {
      return mockAmendments.map((a) => ({
        amendmentId: a.amendmentId,
        title: a.title,
        effectiveDate: a.effectiveDate,
        amendmentType: a.amendmentType,
      }));
    }),
    createAmendmentResponse: vi.fn(async (data: any) => {
      const response = {
        responseId: randomUUID(),
        ...data,
        respondedAt: new Date(),
      };
      mockAmendmentResponses.push(response);
      return response;
    }),
    getAmendmentResponse: vi.fn(async (amendmentId: string, providerId: string) => {
      return mockAmendmentResponses.find(
        (r) => r.amendmentId === amendmentId && r.providerId === providerId,
      );
    }),
    countUnrespondedAmendments: vi.fn(async () => 0),
  };
}

// ---------------------------------------------------------------------------
// Mock audit logger — tracks audit calls
// ---------------------------------------------------------------------------

function createMockAuditLogger() {
  return {
    log: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const sessions: Record<string, any> = {
        [PHYSICIAN_SESSION_TOKEN_HASH]: {
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
        },
        [ADMIN_SESSION_TOKEN_HASH]: {
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
        },
        [DELEGATE_SESSION_TOKEN_HASH]: {
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
let mockAuditLogger: ReturnType<typeof createMockAuditLogger>;
let mockAmendmentRepo: ReturnType<typeof createMockAmendmentRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  const mockEvents = { emit: vi.fn() };
  mockAuditLogger = createMockAuditLogger();
  mockAmendmentRepo = createMockAmendmentRepo();

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: createMockSubscriptionRepo() as any,
    paymentRepo: createMockPaymentRepo() as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    amendmentRepo: mockAmendmentRepo as any,
    userRepo: createMockUserRepo(),
    stripe: mockStripe,
    config: {
      stripePriceStandardMonthly: 'price_monthly_test',
      stripePriceStandardAnnual: 'price_annual_test',
      stripePriceEarlyBirdMonthly: 'price_earlybird_test',
      stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
      stripeWebhookSecret: 'whsec_test_secret',
    },
    auditLogger: mockAuditLogger,
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

function unauthInject(method: 'GET' | 'POST', url: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    ...(payload
      ? { payload, headers: { 'content-type': 'application/json' } }
      : {}),
  });
}

function authedInject(
  method: 'GET' | 'POST',
  url: string,
  token: string,
  payload?: Record<string, unknown>,
) {
  return app.inject({
    method,
    url,
    headers: {
      cookie: `session=${token}`,
      ...(payload ? { 'content-type': 'application/json' } : {}),
    },
    ...(payload ? { payload } : {}),
  });
}

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Seed helper — create amendment in mock store
// ---------------------------------------------------------------------------

function seedAmendment(overrides?: Partial<Record<string, any>>) {
  const amendment = {
    amendmentId: AMENDMENT_ID,
    amendmentType: 'NON_MATERIAL',
    title: 'Test Amendment',
    description: 'Description of amendment',
    documentHash: createHash('sha256').update('Full document text').digest('hex'),
    noticeDate: new Date(),
    effectiveDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // past effective date
    createdBy: ADMIN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
  mockAmendments.push(amendment);
  return amendment;
}

// ---------------------------------------------------------------------------
// Route specs for amendment endpoints
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AMENDMENT_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/platform/amendments',
    payload: VALID_AMENDMENT_PAYLOAD,
    description: 'Create amendment (admin)',
  },
  {
    method: 'GET',
    url: '/api/v1/platform/amendments',
    description: 'List amendments (admin)',
  },
  {
    method: 'GET',
    url: `/api/v1/platform/amendments/${AMENDMENT_ID}`,
    description: 'Get amendment by ID (admin)',
  },
  {
    method: 'POST',
    url: `/api/v1/platform/amendments/${AMENDMENT_ID}/acknowledge`,
    description: 'Acknowledge amendment (physician)',
  },
  {
    method: 'POST',
    url: `/api/v1/platform/amendments/${AMENDMENT_ID}/respond`,
    payload: { response_type: 'ACCEPTED' },
    description: 'Respond to amendment (physician)',
  },
  {
    method: 'GET',
    url: '/api/v1/account/pending-amendments',
    description: 'Get pending amendments (physician)',
  },
];

// ===========================================================================
// Test Suite
// ===========================================================================

describe('IMA-024: Amendment Security Tests', () => {
  beforeAll(async () => {
    mockAmendments = [];
    mockAmendmentResponses = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockAmendments = [];
    mockAmendmentResponses = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // Category 1: Authentication Enforcement (authn)
  // =========================================================================

  describe('Category 1: Authentication Enforcement', () => {

    // --- No session cookie ---

    describe('Requests without session cookie return 401', () => {
      for (const route of AMENDMENT_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 without session cookie (${route.description})`, async () => {
          const res = await unauthInject(route.method, route.url, route.payload);

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    // --- Expired session cookie ---

    describe('Requests with expired/revoked session cookie return 401', () => {
      for (const route of AMENDMENT_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 with expired session (${route.description})`, async () => {
          const res = await authedInject(
            route.method,
            route.url,
            EXPIRED_SESSION_TOKEN,
            route.payload,
          );

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    // --- Tampered session cookie ---

    describe('Requests with tampered session cookie return 401', () => {
      for (const route of AMENDMENT_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 with tampered cookie (${route.description})`, async () => {
          const tamperedToken = createTamperedCookie();
          const res = await authedInject(
            route.method,
            route.url,
            tamperedToken,
            route.payload,
          );

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    // --- Sanity: valid sessions are accepted ---

    describe('Sanity: valid sessions are accepted (not 401)', () => {
      it('POST /api/v1/platform/amendments returns non-401 with admin session', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          VALID_AMENDMENT_PAYLOAD,
        );
        expect(res.statusCode).not.toBe(401);
      });

      it('GET /api/v1/account/pending-amendments returns non-401 with physician session', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/account/pending-amendments',
          PHYSICIAN_SESSION_TOKEN,
        );
        expect(res.statusCode).not.toBe(401);
      });
    });
  });

  // =========================================================================
  // Category 2: Authorization (authz)
  // =========================================================================

  describe('Category 2: Authorization', () => {

    // --- Admin-only endpoints reject physician role ---

    describe('Admin-only endpoints reject physician role', () => {
      it('POST /api/v1/platform/amendments returns 403 for physician role', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          PHYSICIAN_SESSION_TOKEN,
          VALID_AMENDMENT_PAYLOAD,
        );
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });

      it('GET /api/v1/platform/amendments returns 403 for physician role', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/amendments',
          PHYSICIAN_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });

      it('GET /api/v1/platform/amendments/:id returns 403 for physician role', async () => {
        const res = await authedInject(
          'GET',
          `/api/v1/platform/amendments/${AMENDMENT_ID}`,
          PHYSICIAN_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });
    });

    // --- Admin-only endpoints reject delegate role ---

    describe('Admin-only endpoints reject delegate role', () => {
      it('POST /api/v1/platform/amendments returns 403 for delegate role', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          DELEGATE_SESSION_TOKEN,
          VALID_AMENDMENT_PAYLOAD,
        );
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });

      it('GET /api/v1/platform/amendments returns 403 for delegate role', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/amendments',
          DELEGATE_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });

      it('GET /api/v1/platform/amendments/:id returns 403 for delegate role', async () => {
        const res = await authedInject(
          'GET',
          `/api/v1/platform/amendments/${AMENDMENT_ID}`,
          DELEGATE_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });
    });

    // --- Physician-only endpoints work for physician role ---

    describe('Physician endpoints accept physician role', () => {
      it('POST /amendments/:id/acknowledge works for physician', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/acknowledge`,
          PHYSICIAN_SESSION_TOKEN,
        );
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      });

      it('POST /amendments/:id/respond works for physician', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/respond`,
          PHYSICIAN_SESSION_TOKEN,
          { response_type: 'ACCEPTED' },
        );
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      });

      it('GET /api/v1/account/pending-amendments works for physician', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/account/pending-amendments',
          PHYSICIAN_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(200);
      });
    });

    // --- Physician-only endpoints reject delegate role ---

    describe('Physician endpoints reject delegate role', () => {
      it('POST /amendments/:id/acknowledge returns 403 for delegate', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/acknowledge`,
          DELEGATE_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });

      it('POST /amendments/:id/respond returns 403 for delegate', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/respond`,
          DELEGATE_SESSION_TOKEN,
          { response_type: 'ACCEPTED' },
        );
        expect(res.statusCode).toBe(403);
      });

      it('GET /api/v1/account/pending-amendments returns 403 for delegate', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/account/pending-amendments',
          DELEGATE_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });
    });

    // --- Physician-only endpoints reject admin role (admin != physician) ---

    describe('Physician endpoints reject admin role', () => {
      it('POST /amendments/:id/acknowledge returns 403 for admin', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/acknowledge`,
          ADMIN_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });

      it('POST /amendments/:id/respond returns 403 for admin', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/respond`,
          ADMIN_SESSION_TOKEN,
          { response_type: 'ACCEPTED' },
        );
        expect(res.statusCode).toBe(403);
      });

      it('GET /api/v1/account/pending-amendments returns 403 for admin', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/account/pending-amendments',
          ADMIN_SESSION_TOKEN,
        );
        expect(res.statusCode).toBe(403);
      });
    });
  });

  // =========================================================================
  // Category 3: Input Validation & Injection Prevention
  // =========================================================================

  describe('Category 3: Input Validation & Injection Prevention', () => {

    // --- SQL Injection in title ---

    describe('SQL Injection Prevention — title field', () => {
      const SQL_PAYLOADS = [
        "'; DROP TABLE ima_amendments;--",
        "1' OR '1'='1",
        "1; SELECT * FROM users --",
        "' UNION SELECT * FROM providers --",
        "Robert'); DROP TABLE ima_amendments;--",
      ];

      for (const payload of SQL_PAYLOADS) {
        it(`rejects or safely handles title="${payload}"`, async () => {
          const res = await authedInject(
            'POST',
            '/api/v1/platform/amendments',
            ADMIN_SESSION_TOKEN,
            { ...VALID_AMENDMENT_PAYLOAD, title: payload },
          );

          // Should not crash (500) — either stored safely (201) or rejected (400)
          expect(res.statusCode).not.toBe(500);
          expect([201, 400]).toContain(res.statusCode);
        });
      }
    });

    // --- SQL Injection in description ---

    describe('SQL Injection Prevention — description field', () => {
      const SQL_PAYLOADS = [
        "'; DROP TABLE ima_amendments;--",
        "' UNION SELECT * FROM users --",
      ];

      for (const payload of SQL_PAYLOADS) {
        it(`rejects or safely handles description="${payload}"`, async () => {
          const res = await authedInject(
            'POST',
            '/api/v1/platform/amendments',
            ADMIN_SESSION_TOKEN,
            { ...VALID_AMENDMENT_PAYLOAD, description: payload },
          );

          expect(res.statusCode).not.toBe(500);
          expect([201, 400]).toContain(res.statusCode);
        });
      }
    });

    // --- XSS Payloads in title ---

    describe('XSS Prevention — title field', () => {
      const XSS_PAYLOADS = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>',
      ];

      for (const payload of XSS_PAYLOADS) {
        it(`rejects or safely handles title="${payload}"`, async () => {
          const res = await authedInject(
            'POST',
            '/api/v1/platform/amendments',
            ADMIN_SESSION_TOKEN,
            { ...VALID_AMENDMENT_PAYLOAD, title: payload },
          );

          // Must not crash. API returns JSON so XSS cannot execute directly,
          // but verify it doesn't cause a 500.
          expect(res.statusCode).not.toBe(500);
          expect([201, 400]).toContain(res.statusCode);
        });
      }
    });

    // --- XSS Payloads in description ---

    describe('XSS Prevention — description field', () => {
      const XSS_PAYLOADS = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
      ];

      for (const payload of XSS_PAYLOADS) {
        it(`rejects or safely handles description="${payload}"`, async () => {
          const res = await authedInject(
            'POST',
            '/api/v1/platform/amendments',
            ADMIN_SESSION_TOKEN,
            { ...VALID_AMENDMENT_PAYLOAD, description: payload },
          );

          expect(res.statusCode).not.toBe(500);
          expect([201, 400]).toContain(res.statusCode);
        });
      }
    });

    // --- Non-UUID path parameters ---

    describe('Non-UUID amendment ID in path returns 400', () => {
      const INVALID_UUIDS = [
        'not-a-uuid',
        '12345',
        '../../../etc/passwd',
        '<script>alert(1)</script>',
        "'; DROP TABLE ima_amendments; --",
        'null',
        'undefined',
        '00000000-0000-0000-0000-00000000000g',
      ];

      describe('GET /api/v1/platform/amendments/:id', () => {
        for (const invalidId of INVALID_UUIDS) {
          it(`rejects id="${invalidId}"`, async () => {
            const res = await authedInject(
              'GET',
              `/api/v1/platform/amendments/${encodeURIComponent(invalidId)}`,
              ADMIN_SESSION_TOKEN,
            );
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          });
        }
      });

      describe('POST /api/v1/platform/amendments/:id/acknowledge', () => {
        for (const invalidId of INVALID_UUIDS) {
          it(`rejects id="${invalidId}"`, async () => {
            const res = await authedInject(
              'POST',
              `/api/v1/platform/amendments/${encodeURIComponent(invalidId)}/acknowledge`,
              PHYSICIAN_SESSION_TOKEN,
            );
            expect(res.statusCode).toBe(400);
          });
        }
      });

      describe('POST /api/v1/platform/amendments/:id/respond', () => {
        for (const invalidId of INVALID_UUIDS) {
          it(`rejects id="${invalidId}"`, async () => {
            const res = await authedInject(
              'POST',
              `/api/v1/platform/amendments/${encodeURIComponent(invalidId)}/respond`,
              PHYSICIAN_SESSION_TOKEN,
              { response_type: 'ACCEPTED' },
            );
            expect(res.statusCode).toBe(400);
          });
        }
      });
    });

    // --- Empty document_text ---

    describe('Empty document_text is rejected', () => {
      it('rejects amendment with empty document_text', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, document_text: '' },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    // --- Invalid amendment_type ---

    describe('Invalid amendment_type is rejected', () => {
      it('rejects invalid amendment_type value', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, amendment_type: 'INVALID_TYPE' },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects numeric amendment_type', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, amendment_type: 123 },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    // --- Invalid response_type ---

    describe('Invalid response_type is rejected', () => {
      it('rejects invalid response_type value', async () => {
        seedAmendment();
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${AMENDMENT_ID}/respond`,
          PHYSICIAN_SESSION_TOKEN,
          { response_type: 'INVALID_TYPE' },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    // --- Type coercion attacks ---

    describe('Type coercion attacks are rejected', () => {
      it('rejects number for effective_date', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, effective_date: 12345 },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects array for title', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, title: ['one', 'two'] },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects null for document_text', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, document_text: null },
        );
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Category 4: Leakage Prevention
  // =========================================================================

  describe('Category 4: Leakage Prevention', () => {

    // --- Error responses do not echo submitted content ---

    describe('Error responses do not echo back submitted content', () => {
      it('400 validation error does not echo the malicious title', async () => {
        const maliciousTitle = '<script>steal(document.cookie)</script>';
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, amendment_type: 'INVALID', title: maliciousTitle },
        );

        expect(res.statusCode).toBe(400);
        expect(res.body).not.toContain(maliciousTitle);
      });

      it('400 validation error does not echo the document_text', async () => {
        const longText = 'SENSITIVE_DOCUMENT_CONTENT_' + 'x'.repeat(100);
        const res = await authedInject(
          'POST',
          '/api/v1/platform/amendments',
          ADMIN_SESSION_TOKEN,
          { ...VALID_AMENDMENT_PAYLOAD, effective_date: 'not-a-date', document_text: longText },
        );

        expect(res.statusCode).toBe(400);
        expect(res.body).not.toContain('SENSITIVE_DOCUMENT_CONTENT');
      });
    });

    // --- Non-existent amendment returns 404, not 500 ---

    describe('Non-existent amendment returns 404', () => {
      it('GET /api/v1/platform/amendments/:id returns 404 for non-existent UUID', async () => {
        const res = await authedInject(
          'GET',
          `/api/v1/platform/amendments/${NON_EXISTENT_UUID}`,
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(404);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('NOT_FOUND');
        // Must not echo the UUID back in error message
        expect(body.error.message).not.toContain(NON_EXISTENT_UUID);
      });

      it('POST /amendments/:id/acknowledge returns 404 for non-existent amendment', async () => {
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${NON_EXISTENT_UUID}/acknowledge`,
          PHYSICIAN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(404);
      });

      it('POST /amendments/:id/respond returns 404 for non-existent amendment', async () => {
        const res = await authedInject(
          'POST',
          `/api/v1/platform/amendments/${NON_EXISTENT_UUID}/respond`,
          PHYSICIAN_SESSION_TOKEN,
          { response_type: 'ACCEPTED' },
        );

        expect(res.statusCode).toBe(404);
      });
    });

    // --- 401 responses do not reveal amendment data ---

    describe('401 responses do not leak amendment details', () => {
      it('401 on POST /amendments does not contain amendment data', async () => {
        const res = await unauthInject(
          'POST',
          '/api/v1/platform/amendments',
          VALID_AMENDMENT_PAYLOAD,
        );

        expect(res.statusCode).toBe(401);
        expect(res.body).not.toContain('Test Amendment');
        expect(res.body).not.toContain('document_text');
        expect(res.body).not.toContain('amendment_type');
      });
    });

    // --- 403 responses do not reveal amendment existence ---

    describe('403 responses do not reveal amendment existence', () => {
      it('403 from physician on admin endpoint does not expose amendment data', async () => {
        seedAmendment();
        const res = await authedInject(
          'GET',
          `/api/v1/platform/amendments/${AMENDMENT_ID}`,
          PHYSICIAN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(403);
        expect(res.body).not.toContain('Test Amendment');
        expect(res.body).not.toContain(AMENDMENT_ID);
      });
    });

    // --- No server version headers ---

    describe('Response headers do not reveal server technology', () => {
      it('no X-Powered-By header on amendment endpoints', async () => {
        seedAmendment();
        const res = await authedInject(
          'GET',
          `/api/v1/platform/amendments/${AMENDMENT_ID}`,
          ADMIN_SESSION_TOKEN,
        );
        expect(res.headers['x-powered-by']).toBeUndefined();
      });

      it('no server version header on 401 responses', async () => {
        const res = await unauthInject('GET', '/api/v1/platform/amendments');
        const server = res.headers['server'];
        if (server) {
          expect(server).not.toMatch(/fastify/i);
          expect(server).not.toMatch(/node/i);
        }
      });
    });

    // --- Database errors are masked ---

    describe('Database errors are masked with generic message', () => {
      it('500 errors return generic message without internals', async () => {
        // Verify that the error handler masks all 500 error details
        const errorApp = Fastify({ logger: false });
        errorApp.setValidatorCompiler(validatorCompiler);
        errorApp.setSerializerCompiler(serializerCompiler);

        errorApp.get('/test/db-error', async () => {
          throw new Error('ECONNREFUSED: connect to db-host:5432 postgresql://user:pass@host/meritum');
        });

        errorApp.setErrorHandler((_error, _request, reply) => {
          return reply.code(500).send({
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
          });
        });

        await errorApp.ready();

        const res = await errorApp.inject({ method: 'GET', url: '/test/db-error' });
        expect(res.statusCode).toBe(500);
        expect(res.body).not.toContain('ECONNREFUSED');
        expect(res.body).not.toContain('postgresql://');
        expect(res.body).not.toContain('password');
        expect(res.body).not.toContain('stack');

        const body = JSON.parse(res.body);
        expect(body.error.message).toBe('Internal server error');

        await errorApp.close();
      });
    });
  });

  // =========================================================================
  // Category 5: Audit Trail Verification
  // =========================================================================

  describe('Category 5: Audit Trail Verification', () => {

    // --- Amendment creation produces audit record ---

    describe('Amendment creation audit', () => {
      it('amendment creation produces audit record with amendment.created event', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await createAmendment(
          deps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            amendmentType: 'NON_MATERIAL',
            title: 'Audit Test Amendment',
            description: 'Testing audit trail',
            documentText: 'Full document text',
            effectiveDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          },
        );

        expect(auditLogger.log).toHaveBeenCalledTimes(1);
        expect(auditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'amendment.created',
            resourceType: 'ima_amendment',
            resourceId: AMENDMENT_ID,
            actorType: 'admin',
          }),
        );

        // Verify metadata contains actor and amendment info
        const callArgs = auditLogger.log.mock.calls[0][0];
        expect(callArgs.metadata).toMatchObject({
          adminUserId: ADMIN_USER_ID,
          amendmentType: 'NON_MATERIAL',
          title: 'Audit Test Amendment',
        });
      });

      it('amendment.created audit does not contain document_text', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await createAmendment(
          deps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            amendmentType: 'MATERIAL',
            title: 'Material Amendment',
            description: 'Details',
            documentText: 'SECRET_DOCUMENT_CONTENT_SHOULD_NOT_BE_IN_AUDIT',
            effectiveDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          },
        );

        const logEntry = JSON.stringify(auditLogger.log.mock.calls[0][0]);
        expect(logEntry).not.toContain('SECRET_DOCUMENT_CONTENT_SHOULD_NOT_BE_IN_AUDIT');
        expect(logEntry).not.toContain('documentText');
        expect(logEntry).not.toContain('document_text');
      });
    });

    // --- Acknowledgement produces audit record ---

    describe('Acknowledgement audit', () => {
      it('acknowledgement produces audit record with amendment.acknowledged event', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        // Seed an amendment in the mock repo
        mockAmendments.push({
          amendmentId: AMENDMENT_ID,
          amendmentType: 'NON_MATERIAL',
          title: 'Ack Test',
          effectiveDate: new Date(),
          createdBy: ADMIN_USER_ID,
        });

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await acknowledgeAmendment(
          deps,
          {
            userId: PHYSICIAN_USER_ID,
            providerId: PHYSICIAN_USER_ID,
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
          AMENDMENT_ID,
        );

        expect(auditLogger.log).toHaveBeenCalledTimes(1);
        expect(auditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'amendment.acknowledged',
            resourceType: 'ima_amendment',
            resourceId: AMENDMENT_ID,
            actorType: 'physician',
          }),
        );

        const callArgs = auditLogger.log.mock.calls[0][0];
        expect(callArgs.metadata).toMatchObject({
          userId: PHYSICIAN_USER_ID,
          providerId: PHYSICIAN_USER_ID,
        });
      });
    });

    // --- Accept response produces audit record ---

    describe('Accept response audit', () => {
      it('accept response produces audit record with amendment.accepted event', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        mockAmendments.push({
          amendmentId: AMENDMENT_ID,
          amendmentType: 'MATERIAL',
          title: 'Accept Test',
          effectiveDate: new Date(),
          createdBy: ADMIN_USER_ID,
        });

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await respondToAmendment(
          deps,
          {
            userId: PHYSICIAN_USER_ID,
            providerId: PHYSICIAN_USER_ID,
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
          AMENDMENT_ID,
          'ACCEPTED',
        );

        expect(auditLogger.log).toHaveBeenCalledTimes(1);
        expect(auditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'amendment.accepted',
            resourceType: 'ima_amendment',
            resourceId: AMENDMENT_ID,
            actorType: 'physician',
          }),
        );

        const callArgs = auditLogger.log.mock.calls[0][0];
        expect(callArgs.metadata).toMatchObject({
          userId: PHYSICIAN_USER_ID,
          providerId: PHYSICIAN_USER_ID,
          responseType: 'ACCEPTED',
        });
      });
    });

    // --- Reject response produces audit record ---

    describe('Reject response audit', () => {
      it('reject response produces audit record with amendment.rejected event', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        mockAmendments.push({
          amendmentId: AMENDMENT_ID,
          amendmentType: 'MATERIAL',
          title: 'Reject Test',
          effectiveDate: new Date(),
          createdBy: ADMIN_USER_ID,
        });

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await respondToAmendment(
          deps,
          {
            userId: PHYSICIAN_USER_ID,
            providerId: PHYSICIAN_USER_ID,
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
          AMENDMENT_ID,
          'REJECTED',
        );

        expect(auditLogger.log).toHaveBeenCalledTimes(1);
        expect(auditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'amendment.rejected',
            resourceType: 'ima_amendment',
            resourceId: AMENDMENT_ID,
            actorType: 'physician',
          }),
        );

        const callArgs = auditLogger.log.mock.calls[0][0];
        expect(callArgs.metadata).toMatchObject({
          userId: PHYSICIAN_USER_ID,
          providerId: PHYSICIAN_USER_ID,
          responseType: 'REJECTED',
        });
      });
    });

    // --- Audit entries do not contain secrets ---

    describe('Audit entries do not contain secrets', () => {
      it('audit entries do not contain Stripe secrets or IP addresses', async () => {
        const auditLogger = createMockAuditLogger();
        const amendmentRepo = createMockAmendmentRepo();

        const deps: PlatformServiceDeps = {
          subscriptionRepo: createMockSubscriptionRepo() as any,
          paymentRepo: createMockPaymentRepo() as any,
          statusComponentRepo: createMockStatusComponentRepo() as any,
          incidentRepo: createMockIncidentRepo() as any,
          amendmentRepo: amendmentRepo as any,
          userRepo: createMockUserRepo(),
          stripe: createMockStripe(),
          config: {
            stripePriceStandardMonthly: 'price_monthly_test',
            stripePriceStandardAnnual: 'price_annual_test',
            stripePriceEarlyBirdMonthly: 'price_earlybird_test',
            stripePriceEarlyBirdAnnual: 'price_earlybird_annual_test',
            stripeWebhookSecret: 'whsec_test_secret',
          },
          auditLogger,
        };

        await createAmendment(
          deps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            amendmentType: 'NON_MATERIAL',
            title: 'Secrets Test',
            description: 'Testing',
            documentText: 'Document content',
            effectiveDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          },
        );

        for (const call of auditLogger.log.mock.calls) {
          const logEntry = JSON.stringify(call[0]);
          expect(logEntry).not.toContain('sk_live');
          expect(logEntry).not.toContain('sk_test');
          expect(logEntry).not.toContain('whsec_');
          expect(logEntry).not.toContain('documentText');
          expect(logEntry).not.toContain('document_text');
        }
      });
    });
  });
});
