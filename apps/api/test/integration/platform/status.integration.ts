import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

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

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockComponents: Array<Record<string, any>>;
let mockIncidents: Array<Record<string, any>>;
let mockIncidentUpdates: Array<Record<string, any>>;

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
    listComponents: vi.fn(async () => {
      return [...mockComponents].sort((a, b) => a.sortOrder - b.sortOrder);
    }),
    updateComponentStatus: vi.fn(async (componentId: string, status: string) => {
      const comp = mockComponents.find((c) => c.componentId === componentId);
      if (!comp) return undefined;
      comp.status = status;
      comp.updatedAt = new Date();
      return comp;
    }),
    seedComponents: vi.fn(async () => {}),
  };
}

function createMockIncidentRepo() {
  return {
    createIncident: vi.fn(
      async (data: {
        title: string;
        severity: string;
        affectedComponents: string[];
        initialMessage: string;
      }) => {
        const incidentId = randomUUID();
        const now = new Date();
        const updateId = randomUUID();
        const incident = {
          incidentId,
          title: data.title,
          status: 'INVESTIGATING',
          severity: data.severity,
          affectedComponents: data.affectedComponents,
          resolvedAt: null,
          createdAt: now,
          updatedAt: now,
        };
        const update = {
          updateId,
          incidentId,
          status: 'INVESTIGATING',
          message: data.initialMessage,
          createdAt: now,
        };
        mockIncidents.push(incident);
        mockIncidentUpdates.push(update);
        return { ...incident, updates: [update] };
      },
    ),
    updateIncident: vi.fn(
      async (incidentId: string, status: string, message: string) => {
        const incident = mockIncidents.find(
          (i) => i.incidentId === incidentId,
        );
        if (!incident) return undefined;
        incident.status = status;
        incident.updatedAt = new Date();
        if (status === 'RESOLVED') {
          incident.resolvedAt = new Date();
        }
        const updateId = randomUUID();
        const update = {
          updateId,
          incidentId,
          status,
          message,
          createdAt: new Date(),
        };
        mockIncidentUpdates.push(update);
        const updates = mockIncidentUpdates
          .filter((u) => u.incidentId === incidentId)
          .sort(
            (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
          );
        return { ...incident, updates };
      },
    ),
    listActiveIncidents: vi.fn(async () => {
      const active = mockIncidents.filter((i) => i.status !== 'RESOLVED');
      return active.map((i) => ({
        ...i,
        updates: mockIncidentUpdates
          .filter((u) => u.incidentId === i.incidentId)
          .sort(
            (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
          ),
      }));
    }),
    listIncidentHistory: vi.fn(
      async (pagination: { page: number; pageSize: number }) => {
        const sorted = [...mockIncidents].sort(
          (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
        );
        const offset = (pagination.page - 1) * pagination.pageSize;
        const paged = sorted.slice(offset, offset + pagination.pageSize);
        return {
          data: paged.map((i) => ({
            ...i,
            updates: mockIncidentUpdates
              .filter((u) => u.incidentId === i.incidentId)
              .sort(
                (a, b) =>
                  a.createdAt.getTime() - b.createdAt.getTime(),
              ),
          })),
          total: mockIncidents.length,
        };
      },
    ),
    findIncidentById: vi.fn(async (incidentId: string) => {
      const incident = mockIncidents.find(
        (i) => i.incidentId === incidentId,
      );
      if (!incident) return undefined;
      const updates = mockIncidentUpdates
        .filter((u) => u.incidentId === incidentId)
        .sort(
          (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
        );
      return { ...incident, updates };
    }),
  };
}

function createMockUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      if (userId === PHYSICIAN_USER_ID) {
        return {
          userId: PHYSICIAN_USER_ID,
          email: 'dr@example.com',
          fullName: 'Dr. Test',
        };
      }
      if (userId === ADMIN_USER_ID) {
        return {
          userId: ADMIN_USER_ID,
          email: 'admin@meritum.ca',
          fullName: 'Admin User',
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
let mockStatusComponentRepo: ReturnType<typeof createMockStatusComponentRepo>;
let mockIncidentRepo: ReturnType<typeof createMockIncidentRepo>;
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockStripe = createMockStripe();
  mockStatusComponentRepo = createMockStatusComponentRepo();
  mockIncidentRepo = createMockIncidentRepo();
  mockEvents = { emit: vi.fn() };

  const serviceDeps: PlatformServiceDeps = {
    subscriptionRepo: createMockSubscriptionRepo() as any,
    paymentRepo: createMockPaymentRepo() as any,
    statusComponentRepo: mockStatusComponentRepo as any,
    incidentRepo: mockIncidentRepo as any,
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
    if (
      error.statusCode &&
      error.statusCode >= 400 &&
      error.statusCode < 500
    ) {
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
// Seed helpers
// ---------------------------------------------------------------------------

const COMPONENT_1_ID = '00000000-4444-0000-0000-000000000001';
const COMPONENT_2_ID = '00000000-4444-0000-0000-000000000002';

function seedComponents() {
  mockComponents = [
    {
      componentId: COMPONENT_1_ID,
      name: 'WEB_APP',
      displayName: 'Web Application',
      status: 'operational',
      description: null,
      sortOrder: 1,
      updatedAt: new Date(),
    },
    {
      componentId: COMPONENT_2_ID,
      name: 'API',
      displayName: 'API',
      status: 'operational',
      description: null,
      sortOrder: 2,
      updatedAt: new Date(),
    },
  ];
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Platform Status Page Integration Tests', () => {
  beforeAll(async () => {
    mockComponents = [];
    mockIncidents = [];
    mockIncidentUpdates = [];
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockComponents = [];
    mockIncidents = [];
    mockIncidentUpdates = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // GET /api/v1/status — Public Status Page
  // =========================================================================

  describe('GET /api/v1/status', () => {
    it('returns all components and active incidents without auth', async () => {
      seedComponents();

      // Create an active incident
      const incidentId = randomUUID();
      const updateId = randomUUID();
      const now = new Date();
      mockIncidents.push({
        incidentId,
        title: 'API Degradation',
        status: 'INVESTIGATING',
        severity: 'major',
        affectedComponents: [COMPONENT_2_ID],
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      mockIncidentUpdates.push({
        updateId,
        incidentId,
        status: 'INVESTIGATING',
        message: 'We are investigating elevated error rates.',
        createdAt: now,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.components).toHaveLength(2);
      expect(body.data.components[0].name).toBe('WEB_APP');
      expect(body.data.components[0].status).toBe('operational');
      expect(body.data.activeIncidents).toHaveLength(1);
      expect(body.data.activeIncidents[0].title).toBe('API Degradation');
      expect(body.data.activeIncidents[0].updates).toHaveLength(1);
    });

    it('returns empty arrays when no components or incidents exist', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.components).toHaveLength(0);
      expect(body.data.activeIncidents).toHaveLength(0);
    });

    it('does not include resolved incidents in active incidents', async () => {
      seedComponents();

      const now = new Date();
      mockIncidents.push({
        incidentId: randomUUID(),
        title: 'Resolved Issue',
        status: 'RESOLVED',
        severity: 'minor',
        affectedComponents: [COMPONENT_1_ID],
        resolvedAt: now,
        createdAt: new Date(now.getTime() - 3600000),
        updatedAt: now,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.activeIncidents).toHaveLength(0);
    });
  });

  // =========================================================================
  // GET /api/v1/status/incidents — Public Incident History
  // =========================================================================

  describe('GET /api/v1/status/incidents', () => {
    it('returns paginated incident history', async () => {
      // Seed multiple incidents
      const now = new Date();
      for (let i = 0; i < 3; i++) {
        const incidentId = randomUUID();
        mockIncidents.push({
          incidentId,
          title: `Incident ${i + 1}`,
          status: i === 0 ? 'RESOLVED' : 'INVESTIGATING',
          severity: 'minor',
          affectedComponents: [COMPONENT_1_ID],
          resolvedAt: i === 0 ? now : null,
          createdAt: new Date(now.getTime() - i * 3600000),
          updatedAt: now,
        });
        mockIncidentUpdates.push({
          updateId: randomUUID(),
          incidentId,
          status: 'INVESTIGATING',
          message: `Initial update for incident ${i + 1}`,
          createdAt: new Date(now.getTime() - i * 3600000),
        });
      }

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents?page=1&page_size=2',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(2);
      expect(body.pagination.total).toBe(3);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.pageSize).toBe(2);
      expect(body.pagination.hasMore).toBe(true);
    });

    it('returns second page of incident history', async () => {
      const now = new Date();
      for (let i = 0; i < 3; i++) {
        const incidentId = randomUUID();
        mockIncidents.push({
          incidentId,
          title: `Incident ${i + 1}`,
          status: 'INVESTIGATING',
          severity: 'minor',
          affectedComponents: [],
          resolvedAt: null,
          createdAt: new Date(now.getTime() - i * 3600000),
          updatedAt: now,
        });
        mockIncidentUpdates.push({
          updateId: randomUUID(),
          incidentId,
          status: 'INVESTIGATING',
          message: `Update ${i + 1}`,
          createdAt: new Date(now.getTime() - i * 3600000),
        });
      }

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents?page=2&page_size=2',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.pagination.hasMore).toBe(false);
    });

    it('uses default pagination when no params provided', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.pageSize).toBe(20);
    });

    it('does not require authentication', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents',
      });

      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // GET /api/v1/status/incidents/:id — Public Incident Detail
  // =========================================================================

  describe('GET /api/v1/status/incidents/:id', () => {
    it('returns incident with updates', async () => {
      const incidentId = randomUUID();
      const now = new Date();
      mockIncidents.push({
        incidentId,
        title: 'Database Outage',
        status: 'IDENTIFIED',
        severity: 'critical',
        affectedComponents: [COMPONENT_1_ID],
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      mockIncidentUpdates.push(
        {
          updateId: randomUUID(),
          incidentId,
          status: 'INVESTIGATING',
          message: 'We are investigating the issue.',
          createdAt: new Date(now.getTime() - 60000),
        },
        {
          updateId: randomUUID(),
          incidentId,
          status: 'IDENTIFIED',
          message: 'Root cause identified.',
          createdAt: now,
        },
      );

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/status/incidents/${incidentId}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.incidentId).toBe(incidentId);
      expect(body.data.title).toBe('Database Outage');
      expect(body.data.status).toBe('IDENTIFIED');
      expect(body.data.severity).toBe('critical');
      expect(body.data.updates).toHaveLength(2);
      expect(body.data.updates[0].status).toBe('INVESTIGATING');
      expect(body.data.updates[1].status).toBe('IDENTIFIED');
    });

    it('returns 404 for non-existent incident', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/status/incidents/${fakeId}`,
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/status/incidents/not-a-uuid',
      });

      expect(res.statusCode).toBe(400);
    });

    it('does not require authentication', async () => {
      const incidentId = randomUUID();
      const now = new Date();
      mockIncidents.push({
        incidentId,
        title: 'Test Incident',
        status: 'INVESTIGATING',
        severity: 'minor',
        affectedComponents: [],
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      mockIncidentUpdates.push({
        updateId: randomUUID(),
        incidentId,
        status: 'INVESTIGATING',
        message: 'Looking into it.',
        createdAt: now,
      });

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/status/incidents/${incidentId}`,
      });

      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // POST /api/v1/admin/incidents — Create Incident (Admin Only)
  // =========================================================================

  describe('POST /api/v1/admin/incidents', () => {
    it('creates incident (admin only)', async () => {
      seedComponents();

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Scheduled Maintenance',
          severity: 'minor',
          affected_components: [COMPONENT_1_ID],
          message: 'Performing scheduled maintenance on the web application.',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.title).toBe('Scheduled Maintenance');
      expect(body.data.severity).toBe('minor');
      expect(body.data.status).toBe('INVESTIGATING');
      expect(body.data.updates).toHaveLength(1);
      expect(body.data.updates[0].message).toBe(
        'Performing scheduled maintenance on the web application.',
      );
    });

    it('rejects non-admin (physician)', async () => {
      seedComponents();

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Test Incident',
          severity: 'minor',
          affected_components: [COMPONENT_1_ID],
          message: 'Should not be allowed.',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('rejects non-admin (delegate)', async () => {
      seedComponents();

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Test Incident',
          severity: 'minor',
          affected_components: [COMPONENT_1_ID],
          message: 'Should not be allowed.',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        payload: {
          title: 'Test Incident',
          severity: 'minor',
          affected_components: [COMPONENT_1_ID],
          message: 'Should not be allowed.',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 with invalid payload (missing title)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          severity: 'minor',
          affected_components: [COMPONENT_1_ID],
          message: 'Missing title.',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 with invalid severity', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Test',
          severity: 'ultra_critical',
          affected_components: [COMPONENT_1_ID],
          message: 'Invalid severity.',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 with non-UUID affected_components', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Test',
          severity: 'minor',
          affected_components: ['not-a-uuid'],
          message: 'Invalid component id.',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('updates affected component statuses on creation', async () => {
      seedComponents();

      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/incidents',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          title: 'Critical Outage',
          severity: 'critical',
          affected_components: [COMPONENT_1_ID],
          message: 'Major outage detected.',
        },
      });

      expect(mockStatusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(
        COMPONENT_1_ID,
        'MAJOR_OUTAGE',
      );
    });
  });

  // =========================================================================
  // POST /api/v1/admin/incidents/:id/updates — Update Incident (Admin Only)
  // =========================================================================

  describe('POST /api/v1/admin/incidents/:id/updates', () => {
    it('posts update to existing incident', async () => {
      seedComponents();

      // Create an incident first
      const incidentId = randomUUID();
      const now = new Date();
      mockIncidents.push({
        incidentId,
        title: 'Ongoing Issue',
        status: 'INVESTIGATING',
        severity: 'major',
        affectedComponents: [COMPONENT_1_ID],
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      mockIncidentUpdates.push({
        updateId: randomUUID(),
        incidentId,
        status: 'INVESTIGATING',
        message: 'Initial report.',
        createdAt: now,
      });

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${incidentId}/updates`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'identified',
          message: 'Root cause identified: database connection pool exhaustion.',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('IDENTIFIED');
      expect(body.data.updates.length).toBeGreaterThanOrEqual(2);
    });

    it('returns 404 for non-existent incident', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${fakeId}/updates`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'identified',
          message: 'Should not work.',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('rejects non-admin', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${fakeId}/updates`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'identified',
          message: 'Should not be allowed.',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${fakeId}/updates`,
        payload: {
          status: 'identified',
          message: 'No session.',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 with invalid status', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${fakeId}/updates`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'invalid_status',
          message: 'Bad status value.',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('resolves incident and restores component statuses', async () => {
      seedComponents();

      const incidentId = randomUUID();
      const now = new Date();
      mockIncidents.push({
        incidentId,
        title: 'To Be Resolved',
        status: 'MONITORING',
        severity: 'major',
        affectedComponents: [COMPONENT_1_ID, COMPONENT_2_ID],
        resolvedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      mockIncidentUpdates.push({
        updateId: randomUUID(),
        incidentId,
        status: 'MONITORING',
        message: 'Monitoring fix.',
        createdAt: now,
      });

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/incidents/${incidentId}/updates`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'resolved',
          message: 'Issue fully resolved.',
        },
      });

      expect(res.statusCode).toBe(200);
      // Verify component statuses were restored to operational
      expect(
        mockStatusComponentRepo.updateComponentStatus,
      ).toHaveBeenCalledWith(COMPONENT_1_ID, 'OPERATIONAL');
      expect(
        mockStatusComponentRepo.updateComponentStatus,
      ).toHaveBeenCalledWith(COMPONENT_2_ID, 'OPERATIONAL');
    });
  });

  // =========================================================================
  // PATCH /api/v1/admin/components/:id/status — Update Component Status
  // =========================================================================

  describe('PATCH /api/v1/admin/components/:id/status', () => {
    it('updates component status (admin only)', async () => {
      seedComponents();

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_1_ID}/status`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.componentId).toBe(COMPONENT_1_ID);
      expect(body.data.status).toBe('maintenance');
    });

    it('rejects non-admin (physician)', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_1_ID}/status`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('rejects non-admin (delegate)', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_1_ID}/status`,
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        },
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_1_ID}/status`,
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 404 for non-existent component', async () => {
      const fakeId = randomUUID();
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${fakeId}/status`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 with invalid status', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/admin/components/${COMPONENT_1_ID}/status`,
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'invalid_status',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 with non-UUID component id', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/admin/components/not-a-uuid/status',
        headers: {
          cookie: `session=${ADMIN_SESSION_TOKEN}`,
        },
        payload: {
          status: 'maintenance',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });
});
