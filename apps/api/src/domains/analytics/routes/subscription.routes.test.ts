// ============================================================================
// Domain 8: Subscription Routes — Unit Tests
// Tests: CRUD operations, 409 on duplicate, 404 for wrong provider,
// permission enforcement, provider scoping, audit logging.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach } from 'vitest';

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
import { authPluginFp } from '../../../plugins/auth.plugin.js';
import {
  subscriptionRoutes,
  type SubscriptionRouteDeps,
} from './subscription.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const PHYSICIAN2_ID = '00000000-0000-4000-8000-000000000010';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const DELEGATE_PHYSICIAN_ID = '00000000-0000-4000-8000-000000000003';
const SUBSCRIPTION_ID = '00000000-0000-4000-8000-000000000050';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Mock subscription fixture
// ---------------------------------------------------------------------------

function makeSubscription(overrides: Record<string, any> = {}) {
  return {
    subscriptionId: SUBSCRIPTION_ID,
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

function makeSessionDeps(
  userId: string,
  role: string,
  delegateContext?: Record<string, unknown>,
  sessionHash?: string,
) {
  const userObj: any = {
    userId,
    role,
    subscriptionStatus: 'ACTIVE',
  };
  if (delegateContext) {
    userObj.delegateContext = delegateContext;
  }

  const hash = sessionHash ?? SESSION_HASH;

  return {
    sessionRepo: {
      findSessionByTokenHash: async (h: string) => {
        if (h !== hash) return undefined;
        return {
          session: {
            sessionId: 'sess-1',
            userId,
            tokenHash: hash,
            ipAddress: '127.0.0.1',
            userAgent: 'test',
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
            revokedReason: null,
          },
          user: userObj,
        };
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: {
      appendAuditLog: async () => {},
    },
    events: {
      emit: () => true,
      on: () => {},
    },
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

async function buildTestApp(
  deps: SubscriptionRouteDeps,
  opts: {
    userId?: string;
    role?: string;
    delegateContext?: Record<string, unknown>;
    sessionHash?: string;
  } = {},
): Promise<FastifyInstance> {
  const userId = opts.userId ?? PHYSICIAN_ID;
  const role = opts.role ?? 'physician';

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(
    userId,
    role,
    opts.delegateContext,
    opts.sessionHash,
  );
  await app.register(authPluginFp, { sessionDeps } as any);

  await app.register(subscriptionRoutes, { deps });
  await app.ready();

  return app;
}

function authedGet(app: FastifyInstance, url: string, token = SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPost(
  app: FastifyInstance,
  url: string,
  body: any,
  token = SESSION_TOKEN,
) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    body,
  });
}

function authedPut(
  app: FastifyInstance,
  url: string,
  body: any,
  token = SESSION_TOKEN,
) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    body,
  });
}

function authedDelete(
  app: FastifyInstance,
  url: string,
  token = SESSION_TOKEN,
) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${token}` },
  });
}

// ============================================================================
// Tests
// ============================================================================

describe('Subscription Routes', () => {
  // -----------------------------------------------------------------------
  // GET /api/v1/report-subscriptions
  // -----------------------------------------------------------------------

  describe('GET /api/v1/report-subscriptions', () => {
    it('returns all subscriptions for authenticated physician', async () => {
      const subs = [
        makeSubscription(),
        makeSubscription({
          subscriptionId: '00000000-0000-4000-8000-000000000051',
          reportType: 'MONTHLY_PERFORMANCE',
          frequency: 'MONTHLY',
        }),
      ];
      const deps = makeMockDeps({
        subscriptionsRepo: {
          listByProvider: vi.fn().mockResolvedValue(subs),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(2);
      expect(body.data[0].subscription_id).toBe(SUBSCRIPTION_ID);
      expect(body.data[0].report_type).toBe('WEEKLY_SUMMARY');
      expect(body.data[0].frequency).toBe('WEEKLY');
      expect(body.data[0].delivery_method).toBe('IN_APP');
      expect(body.data[0].is_active).toBe(true);
      expect(body.data[0].created_at).toBeDefined();
      expect(body.data[0].updated_at).toBeDefined();

      await app.close();
    });

    it('returns empty array when no subscriptions exist', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          listByProvider: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedGet(app, '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(0);

      await app.close();
    });

    it('scopes query to authenticated provider', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          listByProvider: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps);

      await authedGet(app, '/api/v1/report-subscriptions');

      expect(deps.subscriptionsRepo.listByProvider).toHaveBeenCalledWith(
        PHYSICIAN_ID,
      );

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedGet(
        app,
        '/api/v1/report-subscriptions',
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without REPORT_VIEW permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['ANALYTICS_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedGet(app, '/api/v1/report-subscriptions');

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('uses delegate physician context for scoping', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          listByProvider: vi.fn().mockResolvedValue([]),
        },
      });
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      await authedGet(app, '/api/v1/report-subscriptions');

      expect(deps.subscriptionsRepo.listByProvider).toHaveBeenCalledWith(
        DELEGATE_PHYSICIAN_ID,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/report-subscriptions
  // -----------------------------------------------------------------------

  describe('POST /api/v1/report-subscriptions', () => {
    it('creates subscription with valid body and returns 201', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        delivery_method: 'IN_APP',
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.subscription_id).toBe(SUBSCRIPTION_ID);
      expect(body.data.report_type).toBe('WEEKLY_SUMMARY');
      expect(body.data.frequency).toBe('WEEKLY');
      expect(body.data.delivery_method).toBe('IN_APP');
      expect(deps.subscriptionsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PHYSICIAN_ID,
          reportType: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          deliveryMethod: 'IN_APP',
        }),
      );

      await app.close();
    });

    it('defaults delivery_method to IN_APP when not provided', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'MONTHLY_PERFORMANCE',
        frequency: 'MONTHLY',
      });

      expect(res.statusCode).toBe(201);
      expect(deps.subscriptionsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          deliveryMethod: 'IN_APP',
        }),
      );

      await app.close();
    });

    it('returns 409 when subscription for report_type already exists', async () => {
      const duplicateError: any = new Error('duplicate key');
      duplicateError.code = '23505';
      duplicateError.constraint =
        'report_subscriptions_provider_report_type_uniq';

      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockRejectedValue(duplicateError),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('CONFLICT');
      expect(body.error.message).toContain('already exists');

      await app.close();
    });

    it('logs SUBSCRIPTION_CREATED audit event', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
        delivery_method: 'EMAIL',
      });

      await new Promise((r) => setTimeout(r, 10));

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_created',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({
            subscriptionId: SUBSCRIPTION_ID,
            reportType: 'WEEKLY_SUMMARY',
            frequency: 'WEEKLY',
            deliveryMethod: 'EMAIL',
          }),
        }),
      );

      await app.close();
    });

    it('rejects missing report_type with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(400);
      expect(deps.subscriptionsRepo.create).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects missing frequency with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-subscribable report type (DATA_PORTABILITY) with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'DATA_PORTABILITY',
        frequency: 'MONTHLY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid frequency with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'HOURLY',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid delivery_method with 400', async () => {
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

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPost(
        app,
        '/api/v1/report-subscriptions',
        {
          report_type: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
        },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);
      expect(deps.subscriptionsRepo.create).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 403 for delegate without REPORT_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('scopes to delegate physician context', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockResolvedValue(
            makeSubscription({ providerId: DELEGATE_PHYSICIAN_ID }),
          ),
        },
      });
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_EXPORT'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(201);
      expect(deps.subscriptionsRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: DELEGATE_PHYSICIAN_ID,
        }),
      );

      await app.close();
    });

    it('re-throws non-constraint errors', async () => {
      const genericError = new Error('connection lost');
      const deps = makeMockDeps({
        subscriptionsRepo: {
          create: vi.fn().mockRejectedValue(genericError),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPost(app, '/api/v1/report-subscriptions', {
        report_type: 'WEEKLY_SUMMARY',
        frequency: 'WEEKLY',
      });

      expect(res.statusCode).toBe(500);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // PUT /api/v1/report-subscriptions/:id
  // -----------------------------------------------------------------------

  describe('PUT /api/v1/report-subscriptions/:id', () => {
    it('updates subscription and returns 200', async () => {
      const updated = makeSubscription({
        frequency: 'MONTHLY',
        updatedAt: new Date(),
      });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(updated),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.subscription_id).toBe(SUBSCRIPTION_ID);
      expect(body.data.frequency).toBe('MONTHLY');

      await app.close();
    });

    it('passes update fields correctly to repository', async () => {
      const updated = makeSubscription({
        frequency: 'DAILY',
        deliveryMethod: 'EMAIL',
        isActive: false,
      });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(updated),
        },
      });
      const app = await buildTestApp(deps);

      await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        {
          frequency: 'DAILY',
          delivery_method: 'EMAIL',
          is_active: false,
        },
      );

      expect(deps.subscriptionsRepo.update).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        PHYSICIAN_ID,
        expect.objectContaining({
          frequency: 'DAILY',
          deliveryMethod: 'EMAIL',
          isActive: false,
        }),
      );

      await app.close();
    });

    it('returns 404 when subscription not found or wrong provider', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(null),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('logs SUBSCRIPTION_UPDATED audit event', async () => {
      const updated = makeSubscription({ frequency: 'MONTHLY' });
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(updated),
        },
      });
      const app = await buildTestApp(deps);

      await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      await new Promise((r) => setTimeout(r, 10));

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_updated',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({
            subscriptionId: SUBSCRIPTION_ID,
            changes: { frequency: 'MONTHLY' },
          }),
        }),
      );

      await app.close();
    });

    it('does not log audit when update returns 404', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(null),
        },
      });
      const app = await buildTestApp(deps);

      await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(deps.auditLog).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects empty body (no fields) with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-UUID id with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        '/api/v1/report-subscriptions/not-a-uuid',
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid frequency with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'HOURLY' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without REPORT_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('scopes update to authenticated provider', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockResolvedValue(null),
        },
      });
      const app = await buildTestApp(deps);

      await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(deps.subscriptionsRepo.update).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // DELETE /api/v1/report-subscriptions/:id
  // -----------------------------------------------------------------------

  describe('DELETE /api/v1/report-subscriptions/:id', () => {
    it('deletes subscription and returns 204', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockResolvedValue(true),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(204);
      expect(res.body).toBe('');

      await app.close();
    });

    it('returns 404 when subscription not found or wrong provider', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockResolvedValue(false),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('logs SUBSCRIPTION_CANCELLED audit event', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockResolvedValue(true),
        },
      });
      const app = await buildTestApp(deps);

      await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      await new Promise((r) => setTimeout(r, 10));

      expect(deps.auditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'analytics.subscription_cancelled',
          providerId: PHYSICIAN_ID,
          details: expect.objectContaining({
            subscriptionId: SUBSCRIPTION_ID,
          }),
        }),
      );

      await app.close();
    });

    it('does not log audit when delete returns 404', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockResolvedValue(false),
        },
      });
      const app = await buildTestApp(deps);

      await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(deps.auditLog).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects non-UUID id with 400', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        '/api/v1/report-subscriptions/not-a-uuid',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without REPORT_EXPORT permission', async () => {
      const deps = makeMockDeps();
      const app = await buildTestApp(deps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: DELEGATE_PHYSICIAN_ID,
          permissions: ['REPORT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('scopes delete to authenticated provider', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockResolvedValue(false),
        },
      });
      const app = await buildTestApp(deps);

      await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(deps.subscriptionsRepo.delete).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Tenant isolation — cross-provider access
  // -----------------------------------------------------------------------

  describe('Tenant isolation', () => {
    it('PUT returns 404 for another physician\'s subscription', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          update: vi.fn().mockImplementation(
            (subscriptionId: string, providerId: string) => {
              if (providerId === PHYSICIAN2_ID) {
                return makeSubscription({ providerId: PHYSICIAN2_ID });
              }
              return null;
            },
          ),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedPut(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
        { frequency: 'MONTHLY' },
      );

      expect(res.statusCode).toBe(404);
      expect(deps.subscriptionsRepo.update).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });

    it('DELETE returns 404 for another physician\'s subscription', async () => {
      const deps = makeMockDeps({
        subscriptionsRepo: {
          delete: vi.fn().mockImplementation(
            (subscriptionId: string, providerId: string) => {
              if (providerId === PHYSICIAN2_ID) return true;
              return false;
            },
          ),
        },
      });
      const app = await buildTestApp(deps);

      const res = await authedDelete(
        app,
        `/api/v1/report-subscriptions/${SUBSCRIPTION_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(deps.subscriptionsRepo.delete).toHaveBeenCalledWith(
        SUBSCRIPTION_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });
  });
});
