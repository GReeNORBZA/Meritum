import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (before any imports that read env vars)
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

import {
  authPluginFp,
} from '../../../src/plugins/auth.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import {
  type PlatformHandlerDeps,
} from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type AuditLogger,
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

// Admin user
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000bb0001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000bb0001';

// Physician user
const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000bb0002';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000bb0002';

// Second physician (affected custodian)
const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000bb0003';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockBreaches: Array<Record<string, any>>;
let mockAffectedCustodians: Array<Record<string, any>>;
let mockBreachUpdates: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Session Repo
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
      };
      return sessions[tokenHash] ?? undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock Breach Repo
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
// Mock minimal platform deps
// ---------------------------------------------------------------------------

function createMockPlatformServiceDeps(
  breachRepo: BreachRepository,
): PlatformServiceDeps {
  return {
    subscriptionRepo: {} as any,
    paymentRepo: {} as any,
    statusComponentRepo: {} as any,
    incidentRepo: {} as any,
    breachRepo,
    userRepo: {
      findUserById: vi.fn(async () => undefined),
      updateSubscriptionStatus: vi.fn(async () => {}),
    },
    stripe: {} as any,
    config: {
      stripePriceStandardMonthly: 'price_std_m',
      stripePriceStandardAnnual: 'price_std_a',
      stripePriceEarlyBirdMonthly: 'price_eb_m',
      stripePriceEarlyBirdAnnual: 'price_eb_a',
      stripeWebhookSecret: 'whsec_test',
    },
    auditLogger: {
      log: vi.fn(async () => {}),
    } as AuditLogger,
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
    affected_provider_ids: [PHYSICIAN_USER_ID, PHYSICIAN2_USER_ID],
  };
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let breachRepo: BreachRepository;
let serviceDeps: PlatformServiceDeps;
let mockEventEmitter: { emit: ReturnType<typeof vi.fn> };

describe('Breach Notification Handlers and Routes', () => {
  beforeAll(async () => {
    mockBreaches = [];
    mockAffectedCustodians = [];
    mockBreachUpdates = [];

    breachRepo = createMockBreachRepo();
    serviceDeps = createMockPlatformServiceDeps(breachRepo);
    mockEventEmitter = { emit: vi.fn() };

    app = Fastify();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    // Register auth plugin
    await app.register(authPluginFp, {
      sessionDeps: {
        sessionRepo: createMockSessionRepo(),
        auditRepo: { appendAuditLog: vi.fn(async () => {}) },
        events: { emit: vi.fn() },
      } as any,
    });

    // Mock Stripe webhook verifier (required by platformRoutes)
    app.decorate('verifyStripeWebhook', async () => {});
    app.decorateRequest('stripeRawBody', undefined);

    // Register platform routes
    const handlerDeps: PlatformHandlerDeps = {
      serviceDeps,
      eventEmitter: mockEventEmitter,
    };
    await app.register(platformRoutes, { deps: handlerDeps });

    await app.ready();
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
  // POST /api/v1/platform/breaches — Create breach
  // =========================================================================

  describe('POST /api/v1/platform/breaches', () => {
    it('creates breach (admin only)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.breachId).toBeDefined();
      expect(body.data.breachDescription).toBe('Unauthorized access to patient records');
      expect(body.data.status).toBe('IDENTIFIED');
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        payload: validBreachPayload(),
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 for invalid payload', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: {
          breach_description: '',  // empty string — fails min(1)
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('adds affected custodians for all provider IDs', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });

      expect(res.statusCode).toBe(201);
      // Verify addAffectedCustodian was called for each provider
      expect(breachRepo.addAffectedCustodian).toHaveBeenCalledTimes(2);
    });
  });

  // =========================================================================
  // GET /api/v1/platform/breaches — List breaches
  // =========================================================================

  describe('GET /api/v1/platform/breaches', () => {
    it('lists breaches (admin only)', async () => {
      // Seed a breach
      mockBreaches.push({
        breachId: crypto.randomUUID(),
        breachDescription: 'Test breach',
        breachDate: new Date(),
        awarenessDate: new Date(),
        status: 'IDENTIFIED',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(1);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(1);
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/platform/breaches/:id — Get breach
  // =========================================================================

  describe('GET /api/v1/platform/breaches/:id', () => {
    it('returns breach detail (admin only)', async () => {
      const breachId = crypto.randomUUID();
      mockBreaches.push({
        breachId,
        breachDescription: 'Detailed breach',
        breachDate: new Date(),
        awarenessDate: new Date(),
        status: 'IDENTIFIED',
        contactName: 'Officer',
        contactEmail: 'officer@meritum.ca',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/platform/breaches/${breachId}`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.breachId).toBe(breachId);
      expect(body.data.updates).toBeDefined();
    });

    it('returns 404 for non-existent breach', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000099',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches/not-a-uuid',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000099',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // POST /api/v1/platform/breaches/:id/notify — Send notifications
  // =========================================================================

  describe('POST /api/v1/platform/breaches/:id/notify', () => {
    it('sends notifications (admin only)', async () => {
      // Create a breach via the handler to have proper data
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });
      expect(createRes.statusCode).toBe(201);
      const breachId = JSON.parse(createRes.body).data.breachId;

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/breaches/${breachId}/notify`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notified).toBeGreaterThanOrEqual(0);
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/notify',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/notify',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/platform/breaches/:id/updates — Add update
  // =========================================================================

  describe('POST /api/v1/platform/breaches/:id/updates', () => {
    it('adds supplementary update (admin only)', async () => {
      // Create a breach first
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });
      const breachId = JSON.parse(createRes.body).data.breachId;

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/breaches/${breachId}/updates`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: { content: 'Investigation ongoing, additional measures deployed.' },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.updateId).toBeDefined();
      expect(body.data.content).toBe('Investigation ongoing, additional measures deployed.');
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/updates',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { content: 'Should be denied' },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/updates',
        payload: { content: 'Should be denied' },
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 for empty content', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/updates',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: { content: '' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // POST /api/v1/platform/breaches/:id/resolve — Resolve breach
  // =========================================================================

  describe('POST /api/v1/platform/breaches/:id/resolve', () => {
    it('resolves breach (admin only)', async () => {
      // Create a breach first
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
        payload: validBreachPayload(),
      });
      const breachId = JSON.parse(createRes.body).data.breachId;

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/platform/breaches/${breachId}/resolve`,
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('RESOLVED');
    });

    it('returns 403 for physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/resolve',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000001/resolve',
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 404 for non-existent breach', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/platform/breaches/00000000-0000-0000-0000-000000000099/resolve',
        headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });
});
