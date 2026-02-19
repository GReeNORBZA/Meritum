// ============================================================================
// Domain 8: Analytics Subscriptions — Integration Tests
// End-to-end tests for subscription CRUD, duplicate handling (409),
// update frequency, and list operations.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  subscriptionRoutes,
  type SubscriptionRouteDeps,
} from '../../../src/domains/analytics/routes/subscription.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '30000000-0000-4000-8000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');
const SUB_ID_1 = '30000000-0000-4000-8000-000000000010';
const SUB_ID_2 = '30000000-0000-4000-8000-000000000020';

// ---------------------------------------------------------------------------
// Mock subscription fixture
// ---------------------------------------------------------------------------

function makeSubscription(overrides: Record<string, any> = {}) {
  return {
    subscriptionId: SUB_ID_1,
    providerId: PHYSICIAN_ID,
    reportType: 'WEEKLY_SUMMARY',
    frequency: 'WEEKLY',
    deliveryMethod: 'IN_APP',
    isActive: true,
    createdAt: new Date('2026-01-15T10:00:00.000Z'),
    updatedAt: new Date('2026-01-15T10:00:00.000Z'),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock session deps for auth plugin
// ---------------------------------------------------------------------------

function makeSessionDeps(userId: string, role: string) {
  return {
    sessionRepo: {
      findSessionByTokenHash: async (hash: string) => {
        if (hash !== SESSION_HASH) return undefined;
        return {
          session: {
            sessionId: 'sess-1',
            userId,
            tokenHash: SESSION_HASH,
            ipAddress: '127.0.0.1',
            userAgent: 'test',
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
            revokedReason: null,
          },
          user: {
            userId,
            role,
            subscriptionStatus: 'ACTIVE',
          },
        };
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: { appendAuditLog: async () => {} },
    events: { emit: () => true, on: () => {} },
  };
}

// ---------------------------------------------------------------------------
// Default mock deps factory
// ---------------------------------------------------------------------------

function makeMockDeps(
  overrides: Partial<{
    subscriptionsRepo: any;
    auditLog: any;
  }> = {},
): SubscriptionRouteDeps {
  return {
    subscriptionsRepo: {
      create: vi.fn().mockResolvedValue(makeSubscription()),
      getById: vi.fn().mockResolvedValue(null),
      update: vi.fn().mockResolvedValue(null),
      delete: vi.fn().mockResolvedValue(false),
      listByProvider: vi.fn().mockResolvedValue([]),
      getDueSubscriptions: vi.fn().mockResolvedValue([]),
      ...overrides.subscriptionsRepo,
    },
    auditLog: overrides.auditLog ?? vi.fn().mockResolvedValue(undefined),
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(deps: SubscriptionRouteDeps): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(PHYSICIAN_ID, 'physician');
  await app.register(authPluginFp, { sessionDeps } as any);

  await app.register(subscriptionRoutes, { deps });
  await app.ready();

  return app;
}

function authedGet(app: FastifyInstance, url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
  });
}

function authedPost(app: FastifyInstance, url: string, body: any) {
  return app.inject({
    method: 'POST',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
    payload: body,
  });
}

function authedPut(app: FastifyInstance, url: string, body: any) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
    payload: body,
  });
}

function authedDelete(app: FastifyInstance, url: string) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${SESSION_TOKEN}` },
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Analytics Subscriptions — Integration Tests', () => {
  // -------------------------------------------------------------------------
  // Full CRUD lifecycle
  // -------------------------------------------------------------------------

  describe('Subscription CRUD lifecycle', () => {
    it('create -> list -> update -> verify -> delete -> list empty', async () => {
      const sub = makeSubscription();
      const updatedSub = makeSubscription({ frequency: 'MONTHLY', updatedAt: new Date() });
      const auditLog = vi.fn().mockResolvedValue(undefined);

      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockResolvedValue(sub),
          listByProvider: vi.fn()
            .mockResolvedValueOnce([sub])      // after create
            .mockResolvedValueOnce([updatedSub]) // after update
            .mockResolvedValueOnce([]),          // after delete
          update: vi.fn().mockResolvedValue(updatedSub),
          delete: vi.fn().mockResolvedValue(true),
          getById: vi.fn().mockResolvedValue(sub),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
        auditLog,
      });
      const app = await buildTestApp(deps);

      // Step 1: Create subscription
      const createRes = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        delivery_method: 'IN_APP',
      });

      expect(createRes.statusCode).toBe(201);
      const createBody = JSON.parse(createRes.body);
      expect(createBody.data.subscription_id).toBe(SUB_ID_1);
      expect(createBody.data.report_type).toBe('WEEKLY_SUMMARY');
      expect(createBody.data.frequency).toBe('WEEKLY');
      expect(createBody.data.delivery_method).toBe('IN_APP');
      expect(createBody.data.is_active).toBe(true);

      // Audit: SUBSCRIPTION_CREATED
      expect(auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_created',
          providerId: PHYSICIAN_ID,
        }),
      );

      // Step 2: List shows the subscription
      const listRes1 = await authedGet(app, '/api/v1/report-subscriptions');
      expect(listRes1.statusCode).toBe(200);
      const listBody1 = JSON.parse(listRes1.body);
      expect(listBody1.data).toHaveLength(1);
      expect(listBody1.data[0].subscription_id).toBe(SUB_ID_1);

      // Step 3: Update frequency to MONTHLY
      const updateRes = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
        { frequency: 'MONTHLY' },
      );

      expect(updateRes.statusCode).toBe(200);
      const updateBody = JSON.parse(updateRes.body);
      expect(updateBody.data.frequency).toBe('MONTHLY');

      // Audit: SUBSCRIPTION_UPDATED
      expect(auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_updated',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({
            subscriptionId: SUB_ID_1,
          }),
        }),
      );

      // Step 4: Verify update via list
      const listRes2 = await authedGet(app, '/api/v1/report-subscriptions');
      expect(listRes2.statusCode).toBe(200);
      const listBody2 = JSON.parse(listRes2.body);
      expect(listBody2.data[0].frequency).toBe('MONTHLY');

      // Step 5: Delete subscription
      const deleteRes = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
      );
      expect(deleteRes.statusCode).toBe(204);

      // Audit: SUBSCRIPTION_CANCELLED
      expect(auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_cancelled',
          providerId: PHYSICIAN_ID,
        }),
      );

      // Step 6: List is now empty
      const listRes3 = await authedGet(app, '/api/v1/report-subscriptions');
      expect(listRes3.statusCode).toBe(200);
      const listBody3 = JSON.parse(listRes3.body);
      expect(listBody3.data).toHaveLength(0);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Duplicate subscription — 409
  // -------------------------------------------------------------------------

  describe('Duplicate subscription prevention', () => {
    it('returns 409 when creating duplicate subscription for same report_type', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockRejectedValue(
            Object.assign(new Error('duplicate key'), {
              code: '23505',
              constraint: 'report_subscriptions_provider_report_type',
            }),
          ),
          listByProvider: vi.fn().mockResolvedValue([makeSubscription()]),
          update: vi.fn(),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        delivery_method: 'IN_APP',
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('CONFLICT');
      expect(body.error.message).toContain('already exists');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Update operations
  // -------------------------------------------------------------------------

  describe('Update subscription', () => {
    it('updates frequency only', async () => {
      const updatedSub = makeSubscription({ frequency: 'DAILY' });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue([]),
          update: vi.fn().mockResolvedValue(updatedSub),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
        { frequency: 'DAILY' },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.frequency).toBe('DAILY');

      await app.close();
    });

    it('updates delivery_method only', async () => {
      const updatedSub = makeSubscription({ deliveryMethod: 'EMAIL' });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue([]),
          update: vi.fn().mockResolvedValue(updatedSub),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
        { delivery_method: 'EMAIL' },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.delivery_method).toBe('EMAIL');

      await app.close();
    });

    it('deactivates subscription with is_active=false', async () => {
      const updatedSub = makeSubscription({ isActive: false });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue([]),
          update: vi.fn().mockResolvedValue(updatedSub),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
        { is_active: false },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.is_active).toBe(false);

      await app.close();
    });

    it('returns 404 when updating non-existent or wrong-provider subscription', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue([]),
          update: vi.fn().mockResolvedValue(null),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const otherSubId = '99999999-0000-4000-8000-000000000001';
      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${otherSubId}`,
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('rejects update with no fields provided', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Delete operations
  // -------------------------------------------------------------------------

  describe('Delete subscription', () => {
    it('returns 204 on successful deletion', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn(),
          listByProvider: vi.fn().mockResolvedValue([]),
          update: vi.fn(),
          delete: vi.fn().mockResolvedValue(true),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUB_ID_1}`,
      );

      expect(res.statusCode).toBe(204);

      await app.close();
    });

    it('returns 404 when deleting non-existent subscription', async () => {
      const deps = makeMockDeps(); // default delete returns false
      const app = await buildTestApp(deps);

      const nonExistentId = '99999999-0000-4000-8000-000000000002';
      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${nonExistentId}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('rejects non-UUID subscription ID', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedDelete(app, '/api/v1/report-subscriptions/not-a-uuid');

      expect(res.statusCode).toBe(400);

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------

  describe('Validation', () => {
    it('rejects invalid report_type', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'INVALID_TYPE',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects DATA_PORTABILITY as subscribable type', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'DATA_PORTABILITY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid frequency', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'HOURLY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid delivery_method', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        delivery_method: 'SMS',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('defaults delivery_method to IN_APP when not provided', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(201);

      // Verify create was called with IN_APP default
      expect(deps.subscriptionsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          deliveryMethod: 'IN_APP',
        }),
      );

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Multiple subscriptions for different report types
  // -------------------------------------------------------------------------

  describe('Multiple subscriptions', () => {
    it('can create subscriptions for different report types', async () => {
      const sub1 = makeSubscription();
      const sub2 = makeSubscription({
        subscriptionId: SUB_ID_2,
        reportType: 'MONTHLY_PERFORMANCE',
        frequency: 'MONTHLY',
      });

      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn()
            .mockResolvedValueOnce(sub1)
            .mockResolvedValueOnce(sub2),
          listByProvider: vi.fn().mockResolvedValue([sub1, sub2]),
          update: vi.fn(),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      // Create first subscription
      const res1 = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });
      expect(res1.statusCode).toBe(201);

      // Create second subscription (different type — should succeed)
      const res2 = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'MONTHLY_PERFORMANCE',
        frequency: 'MONTHLY',
      });
      expect(res2.statusCode).toBe(201);

      // List shows both
      const listRes = await authedGet(app, '/api/v1/report-subscriptions');
      expect(listRes.statusCode).toBe(200);
      const listBody = JSON.parse(listRes.body);
      expect(listBody.data).toHaveLength(2);

      const types = listBody.data.map((s: any) => s.report_type);
      expect(types).toContain('WEEKLY_SUMMARY');
      expect(types).toContain('MONTHLY_PERFORMANCE');

      await app.close();
    });
  });

  // -------------------------------------------------------------------------
  // Sanitized response format
  // -------------------------------------------------------------------------

  describe('Response format', () => {
    it('returns snake_case fields in response', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockResolvedValue(makeSubscription()),
          listByProvider: vi.fn().mockResolvedValue([makeSubscription()]),
          update: vi.fn(),
          delete: vi.fn(),
          getById: vi.fn(),
          getDueSubscriptions: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const sub = body.data[0];

      // Snake case fields
      expect(sub).toHaveProperty('subscription_id');
      expect(sub).toHaveProperty('provider_id');
      expect(sub).toHaveProperty('report_type');
      expect(sub).toHaveProperty('delivery_method');
      expect(sub).toHaveProperty('is_active');
      expect(sub).toHaveProperty('created_at');
      expect(sub).toHaveProperty('updated_at');

      // No camelCase fields
      expect(sub).not.toHaveProperty('subscriptionId');
      expect(sub).not.toHaveProperty('providerId');
      expect(sub).not.toHaveProperty('reportType');
      expect(sub).not.toHaveProperty('deliveryMethod');
      expect(sub).not.toHaveProperty('isActive');

      await app.close();
    });
  });
});
