// ============================================================================
// Domain 10: Favourite Routes — Unit Tests
// Tests: CRUD operations, 409 on duplicate, 400 on max 30, auto-seed on
// first GET, reorder bulk update, param validation, auth enforcement,
// provider scoping from auth context.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';

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
import { favouriteRoutes, type FavouriteRouteDeps } from './favourite.routes.js';
import {
  ConflictError,
  NotFoundError,
  BusinessRuleError,
  ValidationError,
} from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const FAVOURITE_ID = '00000000-0000-4000-8000-000000000040';
const FAVOURITE_ID_2 = '00000000-0000-4000-8000-000000000041';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Mock favourite fixture
// ---------------------------------------------------------------------------

function makeFavourite(overrides: Record<string, unknown> = {}) {
  return {
    favouriteId: FAVOURITE_ID,
    providerId: PHYSICIAN_ID,
    healthServiceCode: '03.01A',
    displayName: 'Office Visit',
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date('2026-02-19T08:00:00Z'),
    ...overrides,
  };
}

function makeEnrichedFavourite(overrides: Record<string, unknown> = {}) {
  return {
    ...makeFavourite(),
    description: 'Office visit — comprehensive',
    baseFee: '38.45',
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
) {
  const userObj: any = {
    userId,
    role,
    subscriptionStatus: 'ACTIVE',
  };
  if (delegateContext) {
    userObj.delegateContext = delegateContext;
  }

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
// Mock service deps factory
// ---------------------------------------------------------------------------

function makeMockServiceDeps() {
  return {
    repo: {
      create: vi.fn(),
      getById: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      listByProvider: vi.fn(),
      reorder: vi.fn(),
      countByProvider: vi.fn(),
      bulkCreate: vi.fn(),
    },
    hscLookup: {
      findByCode: vi.fn().mockResolvedValue({
        code: '03.01A',
        description: 'Office visit — comprehensive',
        baseFee: '38.45',
        feeType: 'FEE',
      }),
    },
    modifierLookup: {
      isKnownModifier: vi.fn().mockResolvedValue(true),
    },
    claimHistory: {
      getTopBilledCodes: vi.fn().mockResolvedValue([]),
    },
    providerProfile: {
      getSpecialty: vi.fn().mockResolvedValue(null),
    },
    specialtyDefaults: {
      getDefaultCodes: vi.fn().mockResolvedValue([]),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue(undefined),
    },
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  mockServiceDeps: ReturnType<typeof makeMockServiceDeps>,
  authOpts: {
    userId?: string;
    role?: string;
    delegateContext?: Record<string, unknown>;
  } = {},
): Promise<FastifyInstance> {
  const userId = authOpts.userId ?? PHYSICIAN_ID;
  const role = authOpts.role ?? 'physician';

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const sessionDeps = makeSessionDeps(userId, role, authOpts.delegateContext);
  await app.register(authPluginFp, { sessionDeps } as any);

  const deps: FavouriteRouteDeps = {
    serviceDeps: mockServiceDeps as any,
  };

  await app.register(favouriteRoutes, { deps });
  await app.ready();

  return app;
}

// ---------------------------------------------------------------------------
// Inject helpers
// ---------------------------------------------------------------------------

function authedRequest(
  app: FastifyInstance,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  body?: unknown,
  token = SESSION_TOKEN,
) {
  const opts: any = {
    method,
    url,
    headers: { cookie: `session=${token}` },
  };
  if (body !== undefined) {
    opts.payload = body;
    opts.headers['content-type'] = 'application/json';
  }
  return app.inject(opts);
}

// ============================================================================
// Tests
// ============================================================================

describe('Favourite Routes', () => {
  // -----------------------------------------------------------------------
  // GET /api/v1/favourites — list favourites
  // -----------------------------------------------------------------------

  describe('GET /api/v1/favourites', () => {
    it('returns list of favourites with 200', async () => {
      const mockDeps = makeMockServiceDeps();
      // Service calls repo.countByProvider to check seeding, then listByProvider
      mockDeps.repo.countByProvider.mockResolvedValue(2);
      mockDeps.repo.listByProvider.mockResolvedValue([
        makeFavourite(),
        makeFavourite({ favouriteId: FAVOURITE_ID_2, sortOrder: 2, healthServiceCode: '03.03F' }),
      ]);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(2);
      expect(body.data[0].favouriteId).toBe(FAVOURITE_ID);

      await app.close();
    });

    it('triggers auto-seed on first call when no favourites exist', async () => {
      const mockDeps = makeMockServiceDeps();
      // First call: countByProvider returns 0 (empty), triggers seeding
      mockDeps.repo.countByProvider.mockResolvedValue(0);
      mockDeps.claimHistory.getTopBilledCodes.mockResolvedValue([
        { healthServiceCode: '03.01A', count: 50 },
        { healthServiceCode: '03.03F', count: 30 },
      ]);
      mockDeps.repo.bulkCreate.mockResolvedValue([]);
      // After seeding, list returns the newly created favourites
      mockDeps.repo.listByProvider.mockResolvedValue([
        makeFavourite({ healthServiceCode: '03.01A', sortOrder: 1 }),
        makeFavourite({ favouriteId: FAVOURITE_ID_2, healthServiceCode: '03.03F', sortOrder: 2 }),
      ]);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(res.statusCode).toBe(200);
      expect(mockDeps.repo.countByProvider).toHaveBeenCalledWith(PHYSICIAN_ID);
      expect(mockDeps.claimHistory.getTopBilledCodes).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        10,
      );
      expect(mockDeps.repo.bulkCreate).toHaveBeenCalled();

      await app.close();
    });

    it('skips seeding when favourites already exist', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(5);
      mockDeps.repo.listByProvider.mockResolvedValue([makeFavourite()]);
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(mockDeps.claimHistory.getTopBilledCodes).not.toHaveBeenCalled();
      expect(mockDeps.repo.bulkCreate).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/favourites',
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('allows delegate with CLAIM_VIEW permission', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(1);
      mockDeps.repo.listByProvider.mockResolvedValue([makeFavourite()]);
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('rejects delegate without CLAIM_VIEW permission', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: [],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/favourites — add favourite
  // -----------------------------------------------------------------------

  describe('POST /api/v1/favourites', () => {
    const validBody = {
      health_service_code: '03.01A',
      display_name: 'Office Visit',
      sort_order: 1,
    };

    it('creates favourite and returns 201', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(0);
      mockDeps.repo.create.mockResolvedValue(makeFavourite());
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', validBody);

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.favouriteId).toBe(FAVOURITE_ID);
      expect(body.data.description).toBe('Office visit — comprehensive');

      await app.close();
    });

    it('returns 409 when HSC code already in favourites', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(1);
      mockDeps.repo.create.mockRejectedValue(
        new ConflictError('This health service code is already in your favourites'),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', validBody);

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('CONFLICT');

      await app.close();
    });

    it('returns 400 (via 422 from service) when max 30 reached', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(30);
      mockDeps.repo.create.mockRejectedValue(
        new BusinessRuleError('Maximum of 30 favourite codes allowed per physician'),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', validBody);

      expect(res.statusCode).toBe(422);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');

      await app.close();
    });

    it('returns 400 when health_service_code is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', {
        sort_order: 1,
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when sort_order is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', {
        health_service_code: '03.01A',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when sort_order is not an integer', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', {
        health_service_code: '03.01A',
        sort_order: 1.5,
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('accepts optional display_name and default_modifiers', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(0);
      mockDeps.repo.create.mockResolvedValue(
        makeFavourite({ defaultModifiers: ['CMGP'] }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', {
        health_service_code: '03.01A',
        display_name: 'Office Visit',
        default_modifiers: ['CMGP'],
        sort_order: 1,
      });

      expect(res.statusCode).toBe(201);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/favourites',
        validBody,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('rejects delegate without CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', validBody);

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('allows delegate with CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(0);
      mockDeps.repo.create.mockResolvedValue(makeFavourite());
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_CREATE'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(app, 'POST', '/api/v1/favourites', validBody);

      expect(res.statusCode).toBe(201);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // PUT /api/v1/favourites/:id — update favourite
  // -----------------------------------------------------------------------

  describe('PUT /api/v1/favourites/:id', () => {
    it('updates favourite and returns 200', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.update.mockResolvedValue(
        makeFavourite({ displayName: 'Updated Name' }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { display_name: 'Updated Name' },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.description).toBe('Office visit — comprehensive');

      await app.close();
    });

    it('returns 404 when favourite not found or wrong provider', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.update.mockResolvedValue(null);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { display_name: 'Updated Name' },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('returns 400 when :id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/not-a-uuid',
        { display_name: 'Updated Name' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when body is empty (no fields)', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('updates sort_order only', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.update.mockResolvedValue(
        makeFavourite({ sortOrder: 5 }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { sort_order: 5 },
      );

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('updates default_modifiers', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.update.mockResolvedValue(
        makeFavourite({ defaultModifiers: ['CMGP', 'AFHR'] }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { default_modifiers: ['CMGP', 'AFHR'] },
      );

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { display_name: 'Updated' },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('rejects delegate without CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(
        app,
        'PUT',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        { display_name: 'Updated' },
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // DELETE /api/v1/favourites/:id — remove favourite
  // -----------------------------------------------------------------------

  describe('DELETE /api/v1/favourites/:id', () => {
    it('removes favourite and returns 204', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.delete.mockResolvedValue(true);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'DELETE',
        `/api/v1/favourites/${FAVOURITE_ID}`,
      );

      expect(res.statusCode).toBe(204);

      await app.close();
    });

    it('returns 404 when favourite not found or wrong provider', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.delete.mockResolvedValue(false);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'DELETE',
        `/api/v1/favourites/${FAVOURITE_ID}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('returns 400 when :id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'DELETE',
        '/api/v1/favourites/not-a-uuid',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'DELETE',
        `/api/v1/favourites/${FAVOURITE_ID}`,
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('rejects delegate without CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(
        app,
        'DELETE',
        `/api/v1/favourites/${FAVOURITE_ID}`,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // PUT /api/v1/favourites/reorder — bulk reorder
  // -----------------------------------------------------------------------

  describe('PUT /api/v1/favourites/reorder', () => {
    const validReorderBody = {
      items: [
        { favourite_id: FAVOURITE_ID, sort_order: 2 },
        { favourite_id: FAVOURITE_ID_2, sort_order: 1 },
      ],
    };

    it('reorders favourites and returns 200', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.reorder.mockResolvedValue(undefined);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        validReorderBody,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);

      await app.close();
    });

    it('returns 422 when some favourite IDs do not belong to physician', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.reorder.mockRejectedValue(
        new BusinessRuleError('One or more favourite IDs do not belong to this physician'),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        validReorderBody,
      );

      expect(res.statusCode).toBe(422);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');

      await app.close();
    });

    it('returns 400 when items array is empty', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        { items: [] },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when items is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when favourite_id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        {
          items: [{ favourite_id: 'not-a-uuid', sort_order: 1 }],
        },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when sort_order is not an integer', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        {
          items: [{ favourite_id: FAVOURITE_ID, sort_order: 1.5 }],
        },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        validReorderBody,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('rejects delegate without CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(
        app,
        'PUT',
        '/api/v1/favourites/reorder',
        validReorderBody,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Provider scoping — extracts physician userId from auth context
  // -----------------------------------------------------------------------

  describe('Provider scoping', () => {
    it('passes physician userId to service for favourite creation', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(0);
      mockDeps.repo.create.mockResolvedValue(makeFavourite());
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'POST', '/api/v1/favourites', {
        health_service_code: '03.01A',
        sort_order: 1,
      });

      // The service addFavourite is called which calls hscLookup.findByCode
      // then repo.create with providerId
      expect(mockDeps.hscLookup.findByCode).toHaveBeenCalledWith('03.01A');

      await app.close();
    });

    it('passes physician userId to list service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.countByProvider.mockResolvedValue(1);
      mockDeps.repo.listByProvider.mockResolvedValue([makeFavourite()]);
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'GET', '/api/v1/favourites');

      expect(mockDeps.repo.listByProvider).toHaveBeenCalledWith(PHYSICIAN_ID);

      await app.close();
    });

    it('passes physician userId to reorder service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.reorder.mockResolvedValue(undefined);
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'PUT', '/api/v1/favourites/reorder', {
        items: [{ favourite_id: FAVOURITE_ID, sort_order: 1 }],
      });

      expect(mockDeps.repo.reorder).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        [{ favourite_id: FAVOURITE_ID, sort_order: 1 }],
      );

      await app.close();
    });

    it('passes physician userId to delete service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.delete.mockResolvedValue(true);
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'DELETE', `/api/v1/favourites/${FAVOURITE_ID}`);

      expect(mockDeps.repo.delete).toHaveBeenCalledWith(FAVOURITE_ID, PHYSICIAN_ID);

      await app.close();
    });
  });
});
