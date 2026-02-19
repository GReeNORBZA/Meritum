// ============================================================================
// Domain 10: Mobile Companion — Authentication Enforcement (Security)
// Verifies every authenticated route returns 401 without valid session.
// 15 routes x 4 auth failure modes = 60 test cases + sanity + leakage checks.
// Sync endpoint (POST /api/v1/sync/claims) excluded — returns 501 regardless.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
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

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { shiftRoutes } from '../../../src/domains/mobile/routes/shift.routes.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { FavouriteRouteDeps } from '../../../src/domains/mobile/routes/favourite.routes.js';
import type { MobileRouteDeps } from '../../../src/domains/mobile/routes/mobile.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const VALID_SESSION_TOKEN = randomBytes(32).toString('hex');
const VALID_SESSION_TOKEN_HASH = hashToken(VALID_SESSION_TOKEN);
const VALID_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const VALID_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// ---------------------------------------------------------------------------
// Mock session repository (consumed by auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub handler deps (not exercised — requests should never reach handlers)
// ---------------------------------------------------------------------------

function createStubShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      shiftRepo: {
        create: vi.fn(),
        findActive: vi.fn(),
        endShift: vi.fn(),
        findById: vi.fn(),
        listByProvider: vi.fn(),
        logPatient: vi.fn(),
        getShiftSummary: vi.fn(),
      } as any,
      claimRepo: {
        createDraftClaim: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
  };
}

function createStubFavouriteDeps(): FavouriteRouteDeps {
  return {
    serviceDeps: {
      favouriteRepo: {
        listByProvider: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        countByProvider: vi.fn(),
        reorder: vi.fn(),
        findById: vi.fn(),
      } as any,
      referenceRepo: {
        findByCode: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
  };
}

function createStubMobileDeps(): MobileRouteDeps {
  return {
    quickClaimServiceDeps: {
      claimRepo: { createDraftClaim: vi.fn() } as any,
      patientRepo: {
        create: vi.fn(),
        findByProvider: vi.fn(),
        findById: vi.fn(),
        getRecentByProvider: vi.fn(),
      } as any,
      referenceRepo: { findByCode: vi.fn() } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
    summaryServiceDeps: {
      summaryRepo: {
        getTodayCounts: vi.fn(),
        getWeekRevenue: vi.fn(),
        getActiveShift: vi.fn(),
        getPendingCount: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(shiftRoutes, { deps: createStubShiftDeps() });
  await testApp.register(favouriteRoutes, { deps: createStubFavouriteDeps() });
  await testApp.register(mobileRoutes, { deps: createStubMobileDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Route specs — all 16 authenticated mobile endpoints
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  // ---- Shift routes (6 endpoints) ----
  {
    method: 'POST',
    url: '/api/v1/shifts',
    payload: { location_id: DUMMY_UUID },
    description: 'Start new shift',
  },
  {
    method: 'GET',
    url: '/api/v1/shifts/active',
    description: 'Get active shift',
  },
  {
    method: 'POST',
    url: `/api/v1/shifts/${DUMMY_UUID}/end`,
    description: 'End active shift',
  },
  {
    method: 'GET',
    url: `/api/v1/shifts/${DUMMY_UUID}/summary`,
    description: 'Get shift summary',
  },
  {
    method: 'GET',
    url: '/api/v1/shifts',
    description: 'List recent shifts',
  },
  {
    method: 'POST',
    url: `/api/v1/shifts/${DUMMY_UUID}/patients`,
    payload: {
      patient_id: DUMMY_UUID,
      health_service_code: '03.04A',
      date_of_service: '2026-02-19',
    },
    description: 'Log patient encounter in shift',
  },

  // ---- Favourite routes (5 endpoints) ----
  {
    method: 'GET',
    url: '/api/v1/favourites',
    description: 'List favourite codes',
  },
  {
    method: 'POST',
    url: '/api/v1/favourites',
    payload: {
      health_service_code: '03.04A',
      display_name: 'Office Visit',
      sort_order: 1,
    },
    description: 'Add favourite code',
  },
  {
    method: 'PUT',
    url: `/api/v1/favourites/${DUMMY_UUID}`,
    payload: { display_name: 'Updated' },
    description: 'Update favourite code',
  },
  {
    method: 'DELETE',
    url: `/api/v1/favourites/${DUMMY_UUID}`,
    description: 'Delete favourite code',
  },
  {
    method: 'PUT',
    url: '/api/v1/favourites/reorder',
    payload: {
      items: [
        { favourite_id: DUMMY_UUID, sort_order: 1 },
      ],
    },
    description: 'Reorder favourite codes',
  },

  // ---- Mobile routes (4 endpoints) ----
  {
    method: 'POST',
    url: '/api/v1/mobile/quick-claim',
    payload: {
      patient_id: DUMMY_UUID,
      health_service_code: '03.04A',
      date_of_service: '2026-02-19',
    },
    description: 'Create quick claim',
  },
  {
    method: 'POST',
    url: '/api/v1/mobile/patients',
    payload: {
      first_name: 'Test',
      last_name: 'Patient',
      phn: '123456789',
      date_of_birth: '1990-01-01',
      gender: 'M',
    },
    description: 'Create mobile patient',
  },
  {
    method: 'GET',
    url: '/api/v1/mobile/recent-patients',
    description: 'Get recent patients',
  },
  {
    method: 'GET',
    url: '/api/v1/mobile/summary',
    description: 'Get mobile summary',
  },
];

// ---------------------------------------------------------------------------
// Assertion: exactly 15 authenticated routes
// (6 shift + 5 favourite + 4 mobile = 15; sync endpoint excluded)
// ---------------------------------------------------------------------------

if (AUTHENTICATED_ROUTES.length !== 15) {
  throw new Error(
    `Expected 15 authenticated routes but found ${AUTHENTICATED_ROUTES.length}. ` +
      'Update the route specs to match the registered mobile routes.',
  );
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile Companion Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Seed a valid user + active session (for sanity checks)
    users.push({
      userId: VALID_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: VALID_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: VALID_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed an expired/revoked session
    sessions.push({
      sessionId: EXPIRED_SESSION_ID,
      userId: VALID_USER_ID,
      tokenHash: EXPIRED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
      lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      revoked: true,
      revokedReason: 'expired_absolute',
    });
  });

  // =========================================================================
  // No Cookie — each route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 without session cookie`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
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
  // Expired/Revoked Cookie — each route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with expired session`, async () => {
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
  // Tampered Cookie — each route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with tampered cookie`, async () => {
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
      it(`${route.method} ${route.url} — returns 401 with empty cookie value`, async () => {
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
        url: '/api/v1/shifts/active',
        headers: { cookie: `token=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/favourites',
        headers: { cookie: `auth=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/summary',
        headers: { cookie: `sid=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (confirms test setup)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/shifts/active returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/shifts/active',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/favourites returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/favourites',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/mobile/summary returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/summary',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Sync endpoint returns 501 regardless of auth state
  // =========================================================================

  describe('Sync endpoint (excluded from auth enforcement)', () => {
    it('POST /api/v1/sync/claims returns 501 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/sync/claims',
        payload: { claims: [] },
      });

      expect(res.statusCode).toBe(501);
      const body = JSON.parse(res.body);
      expect(body.phase).toBe(2);
    });

    it('POST /api/v1/sync/claims returns 501 with valid session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/sync/claims',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
        payload: { claims: [] },
      });

      expect(res.statusCode).toBe(501);
    });
  });

  // =========================================================================
  // 401 response body must not leak mobile/shift/favourite data
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/shifts/active',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/mobile/quick-claim',
        payload: {
          patient_id: DUMMY_UUID,
          health_service_code: '03.04A',
          date_of_service: '2026-02-19',
        },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not leak shift, favourite, or patient data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/summary',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('shift');
      expect(rawBody).not.toContain('favourite');
      expect(rawBody).not.toContain('patient');
      expect(rawBody).not.toContain('claim');
      expect(rawBody).not.toContain('revenue');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/mobile/patients',
        payload: {
          first_name: 'Test',
          last_name: 'Patient',
          phn: '123456789',
          date_of_birth: '1990-01-01',
          gender: 'M',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });
  });
});
