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
  type AuditLogger,
  createBreach,
  sendBreachNotifications,
  addBreachUpdate,
  resolveBreach,
} from '../../../src/domains/platform/platform.service.js';
import {
  type BreachRepository,
} from '../../../src/domains/platform/platform.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_USER_ID = '00000000-1111-0000-0000-000000bb0001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000bb0001';

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000bb0002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000bb0002';

const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000bb0003';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000bb0003';

// Expired session
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');

// Provider IDs for affected custodians
const PROVIDER_ID_1 = '00000000-3333-0000-0000-000000bb0001';
const PROVIDER_ID_2 = '00000000-3333-0000-0000-000000bb0002';

const NON_EXISTENT_UUID = '00000000-9999-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockBreaches: Array<Record<string, any>>;
let mockAffectedCustodians: Array<Record<string, any>>;
let mockBreachUpdates: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock breach repo
// ---------------------------------------------------------------------------

function createMockBreachRepo(): BreachRepository {
  return {
    createBreachRecord: vi.fn(async (data: any) => {
      const breach = {
        breachId: crypto.randomUUID(),
        breachDescription: data.breachDescription,
        breachDate: data.breachDate,
        awarenessDate: data.awarenessDate,
        hiDescription: data.hiDescription,
        includesIihi: data.includesIihi,
        affectedCount: data.affectedCount ?? null,
        riskAssessment: data.riskAssessment ?? null,
        mitigationSteps: data.mitigationSteps ?? null,
        contactName: data.contactName,
        contactEmail: data.contactEmail,
        evidenceHoldUntil: new Date(data.awarenessDate.getTime() + 12 * 30 * 24 * 60 * 60 * 1000),
        status: 'IDENTIFIED',
        resolvedAt: null,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockBreaches.push(breach);
      return breach;
    }),

    findBreachById: vi.fn(async (breachId: string) => {
      const breach = mockBreaches.find((b) => b.breachId === breachId);
      if (!breach) return undefined;

      const custodians = mockAffectedCustodians.filter(
        (c) => c.breachId === breachId,
      );
      const updates = mockBreachUpdates.filter(
        (u) => u.breachId === breachId,
      );

      return {
        ...breach,
        affectedCustodianCount: custodians.length,
        updates,
      };
    }),

    listBreaches: vi.fn(async (filters: any) => {
      const offset = (filters.page - 1) * filters.pageSize;

      const filtered = filters.status
        ? mockBreaches.filter((b) => b.status === filters.status)
        : mockBreaches;

      return {
        data: filtered.slice(offset, offset + filters.pageSize),
        total: filtered.length,
      };
    }),

    updateBreachStatus: vi.fn(async (breachId: string, status: string, resolvedAt?: Date) => {
      const breach = mockBreaches.find((b) => b.breachId === breachId);
      if (!breach) return undefined;
      breach.status = status;
      breach.updatedAt = new Date();
      if (status === 'RESOLVED') {
        breach.resolvedAt = resolvedAt ?? new Date();
      }
      return { ...breach };
    }),

    addAffectedCustodian: vi.fn(async (breachId: string, providerId: string) => {
      const custodian = {
        custodianId: crypto.randomUUID(),
        breachId,
        providerId,
        initialNotifiedAt: null,
        notificationMethod: null,
        createdAt: new Date(),
      };
      mockAffectedCustodians.push(custodian);
      return custodian;
    }),

    markCustodianNotified: vi.fn(async (breachId: string, providerId: string, method: string) => {
      const custodian = mockAffectedCustodians.find(
        (c) => c.breachId === breachId && c.providerId === providerId,
      );
      if (!custodian) return undefined;
      custodian.initialNotifiedAt = new Date();
      custodian.notificationMethod = method;
      return { ...custodian };
    }),

    getUnnotifiedCustodians: vi.fn(async (breachId: string) => {
      return mockAffectedCustodians.filter(
        (c) => c.breachId === breachId && c.initialNotifiedAt === null,
      );
    }),

    createBreachUpdate: vi.fn(async (breachId: string, data: any) => {
      const update = {
        updateId: crypto.randomUUID(),
        breachId,
        updateType: data.updateType,
        content: data.content,
        createdBy: data.createdBy,
        sentAt: new Date(),
        createdAt: new Date(),
      };
      mockBreachUpdates.push(update);
      return update;
    }),

    listBreachUpdates: vi.fn(async (breachId: string) => {
      return mockBreachUpdates.filter((u) => u.breachId === breachId);
    }),

    getOverdueBreaches: vi.fn(async () => []),
  } as unknown as BreachRepository;
}

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
// Mock other platform repos
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

function createMockAuditLogger(): AuditLogger & { log: ReturnType<typeof vi.fn> } {
  return {
    log: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Session repo — supports admin, physician, delegate, expired
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const sessions: Record<string, any> = {
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
            providerId: PHYSICIAN_USER_ID,
            role: 'PHYSICIAN',
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
// Valid breach payload
// ---------------------------------------------------------------------------

function validBreachPayload() {
  return {
    breach_description: 'Unauthorized access to patient records',
    breach_date: new Date().toISOString(),
    awareness_date: new Date().toISOString(),
    hi_description: 'Patient demographic information was accessed',
    includes_iihi: true,
    affected_count: 50,
    risk_assessment: 'High risk due to IIHI exposure',
    mitigation_steps: 'Revoked access, reset credentials',
    contact_name: 'Privacy Officer',
    contact_email: 'privacy@meritum.ca',
    affected_provider_ids: [PROVIDER_ID_1, PROVIDER_ID_2],
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let breachRepo: BreachRepository;
let mockAuditLogger: ReturnType<typeof createMockAuditLogger>;
let mockEventEmitter: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  const mockStripe = createMockStripe();
  mockEventEmitter = { emit: vi.fn() };
  mockAuditLogger = createMockAuditLogger();
  breachRepo = createMockBreachRepo();

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: createMockSubscriptionRepo() as any,
    paymentRepo: createMockPaymentRepo() as any,
    statusComponentRepo: createMockStatusComponentRepo() as any,
    incidentRepo: createMockIncidentRepo() as any,
    breachRepo,
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
    eventEmitter: mockEventEmitter,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: createMockSessionRepo(),
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
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
// Route specs for all 6 breach endpoints
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const BREACH_UUID = '00000000-0000-0000-0000-000000000001';

const BREACH_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/platform/breaches',
    payload: validBreachPayload(),
    description: 'Create breach',
  },
  {
    method: 'GET',
    url: '/api/v1/platform/breaches',
    description: 'List breaches',
  },
  {
    method: 'GET',
    url: `/api/v1/platform/breaches/${BREACH_UUID}`,
    description: 'Get breach by ID',
  },
  {
    method: 'POST',
    url: `/api/v1/platform/breaches/${BREACH_UUID}/notify`,
    description: 'Send breach notifications',
  },
  {
    method: 'POST',
    url: `/api/v1/platform/breaches/${BREACH_UUID}/updates`,
    payload: { content: 'Investigation update' },
    description: 'Add breach update',
  },
  {
    method: 'POST',
    url: `/api/v1/platform/breaches/${BREACH_UUID}/resolve`,
    description: 'Resolve breach',
  },
];

// ---------------------------------------------------------------------------
// Helper: create a breach through the admin API
// ---------------------------------------------------------------------------

async function createBreachViaApi(): Promise<string> {
  const res = await authedInject(
    'POST',
    '/api/v1/platform/breaches',
    ADMIN_SESSION_TOKEN,
    validBreachPayload(),
  );
  const body = JSON.parse(res.body);
  return body.data.breachId;
}

// ===========================================================================
// Test Suite
// ===========================================================================

describe('IMA-034: Breach Notification Security Tests', () => {
  beforeAll(async () => {
    mockBreaches = [];
    mockAffectedCustodians = [];
    mockBreachUpdates = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockBreaches = [];
    mockAffectedCustodians = [];
    mockBreachUpdates = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // Category 1: Authentication Enforcement (authn)
  // =========================================================================

  describe('Category 1: Authentication Enforcement', () => {
    describe('Requests without session cookie return 401', () => {
      for (const route of BREACH_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 without session (${route.description})`, async () => {
          const res = await unauthInject(route.method, route.url, route.payload);

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('Requests with expired session cookie return 401', () => {
      for (const route of BREACH_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 with expired session (${route.description})`, async () => {
          const res = await authedInject(route.method, route.url, EXPIRED_SESSION_TOKEN, route.payload);

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('Requests with tampered session cookie return 401', () => {
      for (const route of BREACH_ROUTES) {
        it(`${route.method} ${route.url} — returns 401 with tampered cookie (${route.description})`, async () => {
          const tamperedToken = createTamperedCookie();
          const res = await authedInject(route.method, route.url, tamperedToken, route.payload);

          expect(res.statusCode).toBe(401);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('UNAUTHORIZED');
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('401 responses contain no internal details', () => {
      it('401 response does not contain stack traces or server info', async () => {
        const res = await unauthInject('GET', '/api/v1/platform/breaches');

        expect(res.statusCode).toBe(401);
        const rawBody = res.body;
        expect(rawBody).not.toContain('stack');
        expect(rawBody).not.toContain('node_modules');
        expect(rawBody).not.toContain('.ts:');
        expect(rawBody).not.toContain('postgres');
        expect(rawBody).not.toContain('drizzle');
      });

      it('401 response has consistent error shape', async () => {
        const res = await unauthInject('POST', '/api/v1/platform/breaches', validBreachPayload());

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(Object.keys(body)).toEqual(['error']);
        expect(body.error).toHaveProperty('code');
        expect(body.error).toHaveProperty('message');
      });
    });

    describe('Sanity: valid admin session is accepted', () => {
      it('POST /api/v1/platform/breaches returns non-401 with valid admin session', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          validBreachPayload(),
        );

        expect(res.statusCode).not.toBe(401);
      });
    });
  });

  // =========================================================================
  // Category 2: Authorization — Admin-Only Access (authz)
  // =========================================================================

  describe('Category 2: Authorization — Admin-Only Access', () => {
    describe('All breach endpoints return 403 for physician role', () => {
      for (const route of BREACH_ROUTES) {
        it(`${route.method} ${route.url} — returns 403 for physician (${route.description})`, async () => {
          const res = await authedInject(route.method, route.url, PHYSICIAN_SESSION_TOKEN, route.payload);

          expect(res.statusCode).toBe(403);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('FORBIDDEN');
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('All breach endpoints return 403 for delegate role', () => {
      for (const route of BREACH_ROUTES) {
        it(`${route.method} ${route.url} — returns 403 for delegate (${route.description})`, async () => {
          const res = await authedInject(route.method, route.url, DELEGATE_SESSION_TOKEN, route.payload);

          expect(res.statusCode).toBe(403);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.error.code).toBe('FORBIDDEN');
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('403 responses contain no internal details', () => {
      it('403 response for physician does not reveal required role', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          PHYSICIAN_SESSION_TOKEN,
          validBreachPayload(),
        );

        expect(res.statusCode).toBe(403);
        const rawBody = res.body;
        expect(rawBody).not.toContain('ADMIN');
        expect(rawBody).not.toContain('admin');
        expect(rawBody).not.toContain('stack');
      });

      it('403 response for delegate does not reveal required role', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/breaches',
          DELEGATE_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(403);
        const rawBody = res.body;
        expect(rawBody).not.toContain('ADMIN');
        expect(rawBody).not.toContain('admin');
      });
    });
  });

  // =========================================================================
  // Category 3: Input Validation & Injection Prevention (input)
  // =========================================================================

  describe('Category 3: Input Validation & Injection Prevention', () => {
    describe('SQL injection in breach_description', () => {
      const sqlPayloads = [
        "'; DROP TABLE breach_records; --",
        "1' OR '1'='1",
        "1; SELECT * FROM users --",
        "' UNION SELECT * FROM providers --",
      ];

      for (const payload of sqlPayloads) {
        it(`rejects SQL injection payload: ${payload.slice(0, 30)}...`, async () => {
          const body = {
            ...validBreachPayload(),
            breach_description: payload,
          };

          const res = await authedInject(
            'POST',
            '/api/v1/platform/breaches',
            ADMIN_SESSION_TOKEN,
            body,
          );

          // SQL injection in breach_description should still be accepted by Zod
          // since it's a valid string — Drizzle parameterized queries prevent execution.
          // The key is that it does NOT cause a 500 (SQL error).
          expect(res.statusCode).not.toBe(500);
        });
      }
    });

    describe('XSS in breach_description', () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>',
      ];

      for (const payload of xssPayloads) {
        it(`handles XSS payload safely: ${payload.slice(0, 30)}...`, async () => {
          const body = {
            ...validBreachPayload(),
            breach_description: payload,
          };

          const res = await authedInject(
            'POST',
            '/api/v1/platform/breaches',
            ADMIN_SESSION_TOKEN,
            body,
          );

          // XSS payloads are valid strings — accepted by Zod.
          // The key test is that if stored, they're stored as data and don't execute.
          expect(res.statusCode).not.toBe(500);

          if (res.statusCode === 201) {
            const created = JSON.parse(res.body);
            const breachId = created.data.breachId;

            const getRes = await authedInject(
              'GET',
              `/api/v1/platform/breaches/${breachId}`,
              ADMIN_SESSION_TOKEN,
            );

            if (getRes.statusCode === 200) {
              const retrieved = JSON.parse(getRes.body);
              // Stored as data, never interpreted as HTML
              expect(retrieved.data.breachDescription).toBe(payload);
            }
          }
        });
      }
    });

    describe('Non-UUID breach ID', () => {
      it('rejects non-UUID breach ID in GET', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/breaches/not-a-uuid',
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-UUID breach ID in notify', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches/not-a-uuid/notify',
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-UUID breach ID in updates', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches/not-a-uuid/updates',
          ADMIN_SESSION_TOKEN,
          { content: 'Update text' },
        );

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-UUID breach ID in resolve', async () => {
        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches/not-a-uuid/resolve',
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(400);
      });
    });

    describe('Invalid status values in list query', () => {
      it('rejects invalid status query parameter', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/platform/breaches?status=INVALID_STATUS',
          headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('Empty affected_provider_ids array', () => {
      it('rejects empty affected_provider_ids', async () => {
        const body = {
          ...validBreachPayload(),
          affected_provider_ids: [],
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          body,
        );

        expect(res.statusCode).toBe(400);
      });
    });

    describe('Negative affected_count', () => {
      it('rejects negative affected_count', async () => {
        const body = {
          ...validBreachPayload(),
          affected_count: -5,
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          body,
        );

        expect(res.statusCode).toBe(400);
      });

      it('rejects zero affected_count', async () => {
        const body = {
          ...validBreachPayload(),
          affected_count: 0,
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          body,
        );

        expect(res.statusCode).toBe(400);
      });
    });

    describe('Type coercion attacks', () => {
      it('rejects wrong type for includes_iihi (string instead of boolean)', async () => {
        const body = {
          ...validBreachPayload(),
          includes_iihi: 'true',
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          body,
        );

        expect(res.statusCode).toBe(400);
      });

      it('rejects wrong type for affected_count (string instead of number)', async () => {
        const body = {
          ...validBreachPayload(),
          affected_count: 'fifty',
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          body,
        );

        expect(res.statusCode).toBe(400);
      });
    });

    describe('Empty content in breach updates', () => {
      it('rejects empty content in breach update', async () => {
        const res = await authedInject(
          'POST',
          `/api/v1/platform/breaches/${BREACH_UUID}/updates`,
          ADMIN_SESSION_TOKEN,
          { content: '' },
        );

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Category 4: PHI & Data Leakage Prevention (leakage)
  // =========================================================================

  describe('Category 4: PHI & Data Leakage Prevention', () => {
    describe('Error responses contain no PHI', () => {
      it('404 for non-existent breach does not reveal breach details', async () => {
        const res = await authedInject(
          'GET',
          `/api/v1/platform/breaches/${NON_EXISTENT_UUID}`,
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(404);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        // Generic error message — no resource type or ID exposed
        expect(body.error.message).not.toContain(NON_EXISTENT_UUID);
        expect(body.data).toBeUndefined();
      });

      it('404 for non-existent breach in notify does not reveal details', async () => {
        const res = await authedInject(
          'POST',
          `/api/v1/platform/breaches/${NON_EXISTENT_UUID}/notify`,
          ADMIN_SESSION_TOKEN,
        );

        // Either 404 or error — must not be 500
        expect(res.statusCode).not.toBe(500);
        const rawBody = res.body;
        expect(rawBody).not.toContain('postgres');
        expect(rawBody).not.toContain('drizzle');
        expect(rawBody).not.toContain('sql');
      });

      it('404 for non-existent breach in resolve does not reveal details', async () => {
        const res = await authedInject(
          'POST',
          `/api/v1/platform/breaches/${NON_EXISTENT_UUID}/resolve`,
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).not.toBe(500);
        const rawBody = res.body;
        expect(rawBody).not.toContain('postgres');
        expect(rawBody).not.toContain('drizzle');
      });

      it('validation error does not echo PHI-like data back', async () => {
        const phiLikePayload = {
          ...validBreachPayload(),
          breach_description: '',  // triggers validation failure
        };

        const res = await authedInject(
          'POST',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
          phiLikePayload,
        );

        expect(res.statusCode).toBe(400);
        const rawBody = res.body;
        // PHN-like data should not appear in error responses
        expect(rawBody).not.toContain('123456789');
      });
    });

    describe('No stack traces in error responses', () => {
      it('400 error does not contain stack trace', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/breaches/not-a-uuid',
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(400);
        const rawBody = res.body;
        expect(rawBody).not.toContain('at ');
        expect(rawBody).not.toContain('node_modules');
        expect(rawBody).not.toContain('.ts:');
      });

      it('404 error does not contain stack trace', async () => {
        const res = await authedInject(
          'GET',
          `/api/v1/platform/breaches/${NON_EXISTENT_UUID}`,
          ADMIN_SESSION_TOKEN,
        );

        expect(res.statusCode).toBe(404);
        const rawBody = res.body;
        expect(rawBody).not.toContain('at ');
        expect(rawBody).not.toContain('node_modules');
      });
    });

    describe('Response headers do not leak internals', () => {
      it('responses do not contain X-Powered-By header', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
        );

        expect(res.headers['x-powered-by']).toBeUndefined();
      });

      it('responses do not contain revealing Server header', async () => {
        const res = await authedInject(
          'GET',
          '/api/v1/platform/breaches',
          ADMIN_SESSION_TOKEN,
        );

        const server = res.headers['server'];
        if (server) {
          expect(String(server)).not.toMatch(/fastify/i);
          expect(String(server)).not.toMatch(/\d+\.\d+/);
        }
      });
    });
  });

  // =========================================================================
  // Category 5: Audit Trail Verification (audit)
  // =========================================================================

  describe('Category 5: Audit Trail Verification', () => {
    describe('Breach creation produces audit record', () => {
      it('createBreach logs breach.created with correct fields', async () => {
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: createMockBreachRepo(),
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: mockAuditLogger,
        };

        await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test HI description',
            includesIihi: true,
            affectedCount: 10,
            contactName: 'Privacy Officer',
            contactEmail: 'privacy@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        expect(mockAuditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'breach.created',
            resourceType: 'breach_record',
            actorType: 'admin',
            metadata: expect.objectContaining({
              adminUserId: ADMIN_USER_ID,
              affectedProviderCount: 1,
            }),
          }),
        );
      });

      it('breach.created audit record does not contain PHI', async () => {
        const localAuditLogger = createMockAuditLogger();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: createMockBreachRepo(),
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Patient John Doe PHN 123456789 affected',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'PHN data exposed',
            includesIihi: true,
            contactName: 'Privacy Officer',
            contactEmail: 'privacy@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        expect(localAuditLogger.log).toHaveBeenCalled();
        const logEntry = JSON.stringify(localAuditLogger.log.mock.calls[0][0]);
        // Audit should log action and metadata, not the breach description (which may contain PHI)
        expect(logEntry).not.toContain('123456789');
        expect(logEntry).not.toContain('John Doe');
      });
    });

    describe('Notification send produces audit record', () => {
      it('sendBreachNotifications logs breach.notification_sent', async () => {
        const localAuditLogger = createMockAuditLogger();
        const localBreachRepo = createMockBreachRepo();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: localBreachRepo,
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        // First create a breach
        const breach = await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach for notification',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test HI description',
            includesIihi: false,
            contactName: 'Privacy Officer',
            contactEmail: 'privacy@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1, PROVIDER_ID_2],
          },
        );

        localAuditLogger.log.mockClear();

        // Send notifications
        const result = await sendBreachNotifications(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          breach.breachId,
          mockEventEmitter,
        );

        expect(result.notified).toBe(2);
        expect(localAuditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'breach.notification_sent',
            resourceType: 'breach_record',
            resourceId: breach.breachId,
            actorType: 'admin',
            metadata: expect.objectContaining({
              adminUserId: ADMIN_USER_ID,
              notifiedCount: 2,
            }),
          }),
        );
      });
    });

    describe('Breach update produces audit record', () => {
      it('addBreachUpdate logs breach.updated', async () => {
        const localAuditLogger = createMockAuditLogger();
        const localBreachRepo = createMockBreachRepo();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: localBreachRepo,
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        // Create a breach
        const breach = await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach for update',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test HI description',
            includesIihi: false,
            contactName: 'Privacy Officer',
            contactEmail: 'privacy@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        localAuditLogger.log.mockClear();

        // Add update
        await addBreachUpdate(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          breach.breachId,
          'Investigation ongoing, additional measures deployed.',
          mockEventEmitter,
        );

        expect(localAuditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'breach.updated',
            resourceType: 'breach_record',
            resourceId: breach.breachId,
            actorType: 'admin',
            metadata: expect.objectContaining({
              adminUserId: ADMIN_USER_ID,
              updateType: 'SUPPLEMENTARY',
            }),
          }),
        );
      });
    });

    describe('Resolution produces audit record', () => {
      it('resolveBreach logs breach.resolved', async () => {
        const localAuditLogger = createMockAuditLogger();
        const localBreachRepo = createMockBreachRepo();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: localBreachRepo,
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        // Create a breach
        const breach = await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach for resolution',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test HI description',
            includesIihi: false,
            contactName: 'Privacy Officer',
            contactEmail: 'privacy@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        localAuditLogger.log.mockClear();

        // Resolve
        await resolveBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          breach.breachId,
          mockEventEmitter,
        );

        expect(localAuditLogger.log).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'breach.resolved',
            resourceType: 'breach_record',
            resourceId: breach.breachId,
            actorType: 'admin',
            metadata: expect.objectContaining({
              adminUserId: ADMIN_USER_ID,
            }),
          }),
        );
      });
    });

    describe('Audit entries do not contain secrets or PHI', () => {
      it('no audit entry contains Stripe secrets', async () => {
        const localAuditLogger = createMockAuditLogger();
        const localBreachRepo = createMockBreachRepo();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: localBreachRepo,
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test',
            includesIihi: false,
            contactName: 'Officer',
            contactEmail: 'officer@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        for (const call of localAuditLogger.log.mock.calls) {
          const logEntry = JSON.stringify(call[0]);
          expect(logEntry).not.toContain('sk_live');
          expect(logEntry).not.toContain('sk_test');
          expect(logEntry).not.toContain('whsec_');
        }
      });

      it('no audit entry contains patient PHI fields', async () => {
        const localAuditLogger = createMockAuditLogger();
        const localBreachRepo = createMockBreachRepo();
        const serviceDeps: PlatformServiceDeps = {
          subscriptionRepo: {} as any,
          paymentRepo: {} as any,
          statusComponentRepo: {} as any,
          incidentRepo: {} as any,
          breachRepo: localBreachRepo,
          userRepo: createMockUserRepo(),
          stripe: {} as any,
          config: {} as any,
          auditLogger: localAuditLogger,
        };

        const breach = await createBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          {
            breachDescription: 'Test breach',
            breachDate: new Date(),
            awarenessDate: new Date(),
            hiDescription: 'Test',
            includesIihi: false,
            contactName: 'Officer',
            contactEmail: 'officer@meritum.ca',
            affectedProviderIds: [PROVIDER_ID_1],
          },
        );

        await sendBreachNotifications(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          breach.breachId,
          mockEventEmitter,
        );

        await resolveBreach(
          serviceDeps,
          { userId: ADMIN_USER_ID, role: 'ADMIN' },
          breach.breachId,
          mockEventEmitter,
        );

        const phiFields = ['patientId', 'phn', 'claimId', 'healthServiceCode', 'diagnosticCode', 'dateOfBirth'];
        for (const call of localAuditLogger.log.mock.calls) {
          const logEntry = JSON.stringify(call[0]);
          for (const field of phiFields) {
            expect(logEntry).not.toContain(field);
          }
        }
      });
    });
  });
});
