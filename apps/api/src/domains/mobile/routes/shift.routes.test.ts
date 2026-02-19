// ============================================================================
// Domain 10: Shift Routes — Unit Tests
// Tests: param validation, 409 on duplicate active shift, 404 for wrong
// provider, 400 for ending non-active shift, role enforcement, service
// method dispatch, provider scoping from auth context.
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
import { shiftRoutes, type ShiftRouteDeps } from './shift.routes.js';
import { MobileShiftStatus } from '@meritum/shared/constants/mobile.constants.js';
import {
  ConflictError,
  NotFoundError,
  BusinessRuleError,
} from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const LOCATION_ID = '00000000-0000-4000-8000-000000000010';
const SHIFT_ID = '00000000-0000-4000-8000-000000000020';
const PATIENT_ID = '00000000-0000-4000-8000-000000000030';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// ---------------------------------------------------------------------------
// Mock shift fixture
// ---------------------------------------------------------------------------

function makeShift(overrides: Record<string, unknown> = {}) {
  return {
    shiftId: SHIFT_ID,
    providerId: PHYSICIAN_ID,
    locationId: LOCATION_ID,
    shiftStart: new Date('2026-02-19T08:00:00Z'),
    shiftEnd: null,
    patientCount: 0,
    estimatedValue: '0',
    status: MobileShiftStatus.ACTIVE,
    createdAt: new Date('2026-02-19T08:00:00Z'),
    ...overrides,
  };
}

function makeShiftSummary(overrides: Record<string, unknown> = {}) {
  return {
    ...makeShift(),
    claims: [],
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
      getActive: vi.fn(),
      getById: vi.fn(),
      endShift: vi.fn(),
      getSummary: vi.fn(),
      list: vi.fn(),
      incrementPatientCount: vi.fn(),
      markReviewed: vi.fn(),
    },
    locationCheck: {
      belongsToPhysician: vi.fn().mockResolvedValue(true),
    },
    claimCreator: {
      createClaimFromShift: vi.fn().mockResolvedValue({ claimId: 'claim-1' }),
    },
    hscEligibility: {
      isEligibleForModifier: vi.fn().mockResolvedValue(true),
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

  const deps: ShiftRouteDeps = {
    serviceDeps: mockServiceDeps as any,
  };

  await app.register(shiftRoutes, { deps });
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

describe('Shift Routes', () => {
  // -----------------------------------------------------------------------
  // POST /api/v1/shifts — start shift
  // -----------------------------------------------------------------------

  describe('POST /api/v1/shifts', () => {
    it('starts a new shift and returns 201', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getActive.mockResolvedValue(null);
      mockDeps.repo.create.mockResolvedValue(makeShift());
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: LOCATION_ID,
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.shiftId).toBe(SHIFT_ID);

      await app.close();
    });

    it('returns 409 when physician already has active shift', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getActive.mockResolvedValue(makeShift());
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: LOCATION_ID,
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('CONFLICT');

      await app.close();
    });

    it('returns 400 when location_id is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {});

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when location_id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: 'not-a-uuid',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 404 when location does not belong to physician', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.locationCheck.belongsToPhysician.mockResolvedValue(false);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: LOCATION_ID,
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/shifts',
        { location_id: LOCATION_ID },
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate role', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['CLAIM_CREATE', 'CLAIM_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: LOCATION_ID,
      });

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/shifts/active — get active shift
  // -----------------------------------------------------------------------

  describe('GET /api/v1/shifts/active', () => {
    it('returns active shift with 200', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getActive.mockResolvedValue(makeShift());
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/shifts/active');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.shiftId).toBe(SHIFT_ID);

      await app.close();
    });

    it('returns 204 when no active shift', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getActive.mockResolvedValue(null);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/shifts/active');

      expect(res.statusCode).toBe(204);
      expect(res.body).toBe('');

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts/active',
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate role', async () => {
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

      const res = await authedRequest(app, 'GET', '/api/v1/shifts/active');

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/shifts/:id/end — end shift
  // -----------------------------------------------------------------------

  describe('POST /api/v1/shifts/:id/end', () => {
    it('ends an active shift and returns summary', async () => {
      const mockDeps = makeMockServiceDeps();
      const endedShift = makeShift({
        status: MobileShiftStatus.ENDED,
        shiftEnd: new Date('2026-02-19T16:00:00Z'),
        patientCount: 3,
        estimatedValue: '450.00',
      });
      mockDeps.repo.getById.mockResolvedValue(makeShift());
      mockDeps.repo.endShift.mockResolvedValue(endedShift);
      mockDeps.repo.getSummary.mockResolvedValue(makeShiftSummary({
        ...endedShift,
        claims: [],
      }));
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/end`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();

      await app.close();
    });

    it('returns 404 when shift not found or wrong provider', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(null);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/end`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');

      await app.close();
    });

    it('returns 422 when shift is not active', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(
        makeShift({ status: MobileShiftStatus.ENDED }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/end`,
      );

      expect(res.statusCode).toBe(422);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');

      await app.close();
    });

    it('returns 400 when :id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/shifts/not-a-uuid/end',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/end`,
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/shifts/:id/summary — shift summary
  // -----------------------------------------------------------------------

  describe('GET /api/v1/shifts/:id/summary', () => {
    it('returns shift summary with linked claims', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getSummary.mockResolvedValue(makeShiftSummary());
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        `/api/v1/shifts/${SHIFT_ID}/summary`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.shiftId).toBe(SHIFT_ID);

      await app.close();
    });

    it('returns 404 when shift not found or wrong provider', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getSummary.mockResolvedValue(null);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        `/api/v1/shifts/${SHIFT_ID}/summary`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');

      await app.close();
    });

    it('returns 400 when :id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts/bad-id/summary',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        `/api/v1/shifts/${SHIFT_ID}/summary`,
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/shifts — list shifts
  // -----------------------------------------------------------------------

  describe('GET /api/v1/shifts', () => {
    it('returns paginated list of shifts', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.list.mockResolvedValue({
        data: [makeShift()],
        total: 1,
      });
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/shifts');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(1);

      await app.close();
    });

    it('passes query filters to service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.list.mockResolvedValue({ data: [], total: 0 });
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts?limit=5&status=ENDED',
      );

      expect(res.statusCode).toBe(200);
      expect(mockDeps.repo.list).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ limit: 5, status: 'ENDED' }),
      );

      await app.close();
    });

    it('uses default limit when not specified', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.list.mockResolvedValue({ data: [], total: 0 });
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(app, 'GET', '/api/v1/shifts');

      expect(res.statusCode).toBe(200);
      expect(mockDeps.repo.list).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ limit: 10 }),
      );

      await app.close();
    });

    it('rejects invalid status value with 400', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts?status=INVALID',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit > 50 with 400', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts?limit=51',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/shifts',
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate role', async () => {
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

      const res = await authedRequest(app, 'GET', '/api/v1/shifts');

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/shifts/:id/patients — log patient
  // -----------------------------------------------------------------------

  describe('POST /api/v1/shifts/:id/patients', () => {
    const validLogBody = {
      patient_id: PATIENT_ID,
      health_service_code: '03.01A',
    };

    it('logs patient and returns 201 with claim data', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(makeShift());
      mockDeps.repo.incrementPatientCount.mockResolvedValue(makeShift({ patientCount: 1 }));
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        validLogBody,
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.claimId).toBeDefined();
      expect(body.data.afterHoursEligible).toBeDefined();

      await app.close();
    });

    it('returns 404 when shift not found', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(null);
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        validLogBody,
      );

      expect(res.statusCode).toBe(404);

      await app.close();
    });

    it('returns 422 when shift is not active', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(
        makeShift({ status: MobileShiftStatus.ENDED }),
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        validLogBody,
      );

      expect(res.statusCode).toBe(422);

      await app.close();
    });

    it('returns 400 when patient_id is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        { health_service_code: '03.01A' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when health_service_code is missing', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        { patient_id: PATIENT_ID },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when :id is not a UUID', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/shifts/not-a-uuid/patients',
        validLogBody,
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('accepts optional modifiers and date_of_service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getById.mockResolvedValue(makeShift());
      mockDeps.repo.incrementPatientCount.mockResolvedValue(makeShift({ patientCount: 1 }));
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        {
          ...validLogBody,
          modifiers: ['CMGP'],
          date_of_service: '2026-02-19',
          quick_note: 'Chest pain eval',
        },
      );

      expect(res.statusCode).toBe(201);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockServiceDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        validLogBody,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate role', async () => {
      const mockDeps = makeMockServiceDeps();
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

      const res = await authedRequest(
        app,
        'POST',
        `/api/v1/shifts/${SHIFT_ID}/patients`,
        validLogBody,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Provider scoping — extracts physician userId from auth context
  // -----------------------------------------------------------------------

  describe('Provider scoping', () => {
    it('passes physician userId to service for shift creation', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.getActive.mockResolvedValue(null);
      mockDeps.repo.create.mockResolvedValue(makeShift());
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'POST', '/api/v1/shifts', {
        location_id: LOCATION_ID,
      });

      expect(mockDeps.locationCheck.belongsToPhysician).toHaveBeenCalledWith(
        LOCATION_ID,
        PHYSICIAN_ID,
      );

      await app.close();
    });

    it('passes physician userId to list service', async () => {
      const mockDeps = makeMockServiceDeps();
      mockDeps.repo.list.mockResolvedValue({ data: [], total: 0 });
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'GET', '/api/v1/shifts');

      expect(mockDeps.repo.list).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.any(Object),
      );

      await app.close();
    });
  });
});
