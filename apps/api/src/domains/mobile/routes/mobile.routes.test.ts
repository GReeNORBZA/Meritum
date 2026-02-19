// ============================================================================
// Domain 10: Mobile Routes — Unit Tests
// Tests: quick claim creates draft, mobile patient creation, recent patients,
// summary response shape, sync returns 501, auth enforcement, validation,
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
import { mobileRoutes, type MobileRouteDeps } from './mobile.routes.js';
import { resetAuditRateLimiter } from '../services/mobile-summary.service.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000002';
const PATIENT_ID = '00000000-0000-4000-8000-000000000030';
const CLAIM_ID = '00000000-0000-4000-8000-000000000040';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

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

function makeMockDeps() {
  return {
    quickClaimServiceDeps: {
      claimCreator: {
        createDraftClaim: vi.fn().mockResolvedValue({ claimId: CLAIM_ID }),
      },
      patientCreator: {
        createMinimalPatient: vi.fn().mockResolvedValue({
          patientId: PATIENT_ID,
          firstName: 'Jane',
          lastName: 'Doe',
          phn: '123456789',
          dateOfBirth: '1990-05-15',
          gender: 'FEMALE',
        }),
      },
      recentPatientsQuery: {
        getRecentBilledPatients: vi.fn().mockResolvedValue([
          {
            patientId: PATIENT_ID,
            firstName: 'Jane',
            lastName: 'Doe',
            phn: '123456789',
          },
        ]),
      },
      auditRepo: {
        appendAuditLog: vi.fn().mockResolvedValue(undefined),
      },
    },
    summaryServiceDeps: {
      claimCounter: {
        countTodayClaims: vi.fn().mockResolvedValue(5),
        countPendingQueue: vi.fn().mockResolvedValue(3),
      },
      unreadCounter: {
        countUnread: vi.fn().mockResolvedValue(2),
      },
      activeShiftLookup: {
        getActive: vi.fn().mockResolvedValue(null),
      },
      auditRepo: {
        appendAuditLog: vi.fn().mockResolvedValue(undefined),
      },
    },
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  mockDeps: ReturnType<typeof makeMockDeps>,
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

  const deps: MobileRouteDeps = {
    quickClaimServiceDeps: mockDeps.quickClaimServiceDeps as any,
    summaryServiceDeps: mockDeps.summaryServiceDeps as any,
  };

  await app.register(mobileRoutes, { deps });
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

function unauthRequest(
  app: FastifyInstance,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown,
) {
  const opts: any = { method, url };
  if (body !== undefined) {
    opts.payload = body;
    opts.headers = { 'content-type': 'application/json' };
  }
  return app.inject(opts);
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const VALID_QUICK_CLAIM = {
  patient_id: PATIENT_ID,
  health_service_code: '03.04A',
  date_of_service: '2026-02-19',
};

const VALID_MOBILE_PATIENT = {
  first_name: 'Jane',
  last_name: 'Doe',
  phn: '123456789',
  date_of_birth: '1990-05-15',
  gender: 'F',
};

// ============================================================================
// Tests
// ============================================================================

describe('Mobile Routes', () => {
  beforeEach(() => {
    resetAuditRateLimiter();
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/mobile/quick-claim — create draft AHCIP claim
  // -----------------------------------------------------------------------

  describe('POST /api/v1/mobile/quick-claim', () => {
    it('creates a draft claim and returns 201', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.claimId).toBe(CLAIM_ID);

      await app.close();
    });

    it('passes correct data to service', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        {
          ...VALID_QUICK_CLAIM,
          modifiers: ['CMGP'],
        },
      );

      expect(
        mockDeps.quickClaimServiceDeps.claimCreator.createDraftClaim,
      ).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          patientId: PATIENT_ID,
          healthServiceCode: '03.04A',
          modifiers: ['CMGP'],
          dateOfService: '2026-02-19',
          claimType: 'AHCIP',
          state: 'DRAFT',
          source: 'mobile_quick_entry',
        }),
      );

      await app.close();
    });

    it('returns 400 when patient_id is missing', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        { health_service_code: '03.04A' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when health_service_code is missing', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        { patient_id: PATIENT_ID },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when patient_id is not a UUID', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        { ...VALID_QUICK_CLAIM, patient_id: 'not-a-uuid' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockDeps();
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
        'POST',
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('allows delegate with CLAIM_CREATE permission', async () => {
      const mockDeps = makeMockDeps();
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
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
      );

      expect(res.statusCode).toBe(201);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/mobile/patients — create minimal patient
  // -----------------------------------------------------------------------

  describe('POST /api/v1/mobile/patients', () => {
    it('creates a patient and returns 201', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        VALID_MOBILE_PATIENT,
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.patientId).toBe(PATIENT_ID);
      expect(body.data.firstName).toBe('Jane');
      expect(body.data.lastName).toBe('Doe');

      await app.close();
    });

    it('passes correct data to service', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        VALID_MOBILE_PATIENT,
      );

      expect(
        mockDeps.quickClaimServiceDeps.patientCreator.createMinimalPatient,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, {
        firstName: 'Jane',
        lastName: 'Doe',
        phn: '123456789',
        dateOfBirth: '1990-05-15',
        gender: 'F',
      });

      await app.close();
    });

    it('returns 400 when first_name is missing', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const { first_name, ...incomplete } = VALID_MOBILE_PATIENT;
      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        incomplete,
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when phn is not 9 digits', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        { ...VALID_MOBILE_PATIENT, phn: '12345' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when phn contains non-numeric characters', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        { ...VALID_MOBILE_PATIENT, phn: '12345ABCD' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when gender is invalid', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        { ...VALID_MOBILE_PATIENT, gender: 'INVALID' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when date_of_birth has invalid format', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        { ...VALID_MOBILE_PATIENT, date_of_birth: '05/15/1990' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        VALID_MOBILE_PATIENT,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without PATIENT_CREATE permission', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['PATIENT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        VALID_MOBILE_PATIENT,
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/mobile/recent-patients — recent patients for quick entry
  // -----------------------------------------------------------------------

  describe('GET /api/v1/mobile/recent-patients', () => {
    it('returns recent patients with 200', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].patientId).toBe(PATIENT_ID);

      await app.close();
    });

    it('uses default limit of 20 when not specified', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(app, 'GET', '/api/v1/mobile/recent-patients');

      expect(
        mockDeps.quickClaimServiceDeps.recentPatientsQuery
          .getRecentBilledPatients,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, 20);

      await app.close();
    });

    it('passes custom limit from query string', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients?limit=5',
      );

      expect(
        mockDeps.quickClaimServiceDeps.recentPatientsQuery
          .getRecentBilledPatients,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, 5);

      await app.close();
    });

    it('returns 400 when limit exceeds 20', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients?limit=21',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 400 when limit is 0', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients?limit=0',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients',
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without PATIENT_VIEW permission', async () => {
      const mockDeps = makeMockDeps();
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
        'GET',
        '/api/v1/mobile/recent-patients',
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/mobile/summary — lightweight KPI summary
  // -----------------------------------------------------------------------

  describe('GET /api/v1/mobile/summary', () => {
    it('returns summary with correct shape', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/summary',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.todayClaimsCount).toBe(5);
      expect(body.data.pendingQueueCount).toBe(3);
      expect(body.data.unreadNotificationsCount).toBe(2);
      expect(body.data.activeShift).toBeNull();

      await app.close();
    });

    it('includes active shift when present', async () => {
      const mockDeps = makeMockDeps();
      mockDeps.summaryServiceDeps.activeShiftLookup.getActive.mockResolvedValue(
        {
          shiftId: '00000000-0000-4000-8000-000000000020',
          shiftStart: new Date('2026-02-19T08:00:00Z'),
          patientCount: 3,
          estimatedValue: '450.00',
        },
      );
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/summary',
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.activeShift).not.toBeNull();
      expect(body.data.activeShift.shiftId).toBe(
        '00000000-0000-4000-8000-000000000020',
      );

      await app.close();
    });

    it('returns 401 without session', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/summary',
        undefined,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);

      await app.close();
    });

    it('returns 403 for delegate without CLAIM_VIEW permission', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps, {
        userId: DELEGATE_USER_ID,
        role: 'delegate',
        delegateContext: {
          delegateUserId: DELEGATE_USER_ID,
          physicianProviderId: PHYSICIAN_ID,
          permissions: ['PATIENT_VIEW'],
          linkageId: 'link-1',
        },
      });

      const res = await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/summary',
      );

      expect(res.statusCode).toBe(403);

      await app.close();
    });

    it('uses physician context for delegates', async () => {
      const mockDeps = makeMockDeps();
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

      await authedRequest(app, 'GET', '/api/v1/mobile/summary');

      expect(
        mockDeps.summaryServiceDeps.claimCounter.countTodayClaims,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, expect.any(Date));

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/sync/claims — Phase 2 placeholder
  // -----------------------------------------------------------------------

  describe('POST /api/v1/sync/claims', () => {
    it('returns 501 Not Implemented', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await authedRequest(
        app,
        'POST',
        '/api/v1/sync/claims',
        { claims: [] },
      );

      expect(res.statusCode).toBe(501);
      const body = JSON.parse(res.body);
      expect(body.message).toBe(
        'Offline sync is not available in this version',
      );
      expect(body.phase).toBe(2);

      await app.close();
    });

    it('returns 501 without authentication', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await unauthRequest(app, 'POST', '/api/v1/sync/claims', {
        claims: [],
      });

      expect(res.statusCode).toBe(501);
      const body = JSON.parse(res.body);
      expect(body.message).toBe(
        'Offline sync is not available in this version',
      );
      expect(body.phase).toBe(2);

      await app.close();
    });

    it('returns 501 with empty body', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      const res = await unauthRequest(app, 'POST', '/api/v1/sync/claims');

      expect(res.statusCode).toBe(501);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Provider scoping — extracts physician ID from auth context
  // -----------------------------------------------------------------------

  describe('Provider scoping', () => {
    it('passes physician userId to quick claim service', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
      );

      expect(
        mockDeps.quickClaimServiceDeps.claimCreator.createDraftClaim,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, expect.any(Object));

      await app.close();
    });

    it('passes physician userId to patient creation service', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/patients',
        VALID_MOBILE_PATIENT,
      );

      expect(
        mockDeps.quickClaimServiceDeps.patientCreator.createMinimalPatient,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, expect.any(Object));

      await app.close();
    });

    it('passes physician userId to recent patients query', async () => {
      const mockDeps = makeMockDeps();
      const app = await buildTestApp(mockDeps);

      await authedRequest(
        app,
        'GET',
        '/api/v1/mobile/recent-patients',
      );

      expect(
        mockDeps.quickClaimServiceDeps.recentPatientsQuery
          .getRecentBilledPatients,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, expect.any(Number));

      await app.close();
    });

    it('extracts physicianProviderId from delegate context', async () => {
      const mockDeps = makeMockDeps();
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

      await authedRequest(
        app,
        'POST',
        '/api/v1/mobile/quick-claim',
        VALID_QUICK_CLAIM,
      );

      expect(
        mockDeps.quickClaimServiceDeps.claimCreator.createDraftClaim,
      ).toHaveBeenCalledWith(PHYSICIAN_ID, expect.any(Object));

      await app.close();
    });
  });
});
