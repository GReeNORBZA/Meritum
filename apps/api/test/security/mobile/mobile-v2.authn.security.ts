// ============================================================================
// Domain 10: Mobile V2 — Authentication Enforcement (Security)
// Verifies every new Phase 9 endpoint returns 401 without valid session.
// 10 routes x 4 auth failure modes = 40 test cases + sanity + leakage checks.
//
// New endpoints:
//   Shift extensions (5): GET /:id, POST /confirm-inferred,
//     POST /:id/encounters, GET /:id/encounters, DELETE /:id/encounters/:eid
//   Schedule routes (5): GET /calendar, GET /, POST /, PUT /:id, DELETE /:id
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
import { scheduleRoutes } from '../../../src/domains/mobile/routes/schedule.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { ScheduleRouteDeps } from '../../../src/domains/mobile/routes/schedule.routes.js';

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
    scheduleDeps: {
      scheduleRepo: {
        create: vi.fn(),
        getById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(),
      } as any,
      shiftRepo: {
        create: vi.fn(),
        getActive: vi.fn(),
      } as any,
      locationCheck: {
        belongsToPhysician: vi.fn(async () => true),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
    encounterDeps: {
      encounterRepo: {
        logEncounter: vi.fn(),
        listEncounters: vi.fn(async () => []),
        deleteEncounter: vi.fn(),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

function createStubScheduleDeps(): ScheduleRouteDeps {
  return {
    serviceDeps: {
      scheduleRepo: {
        create: vi.fn(),
        getById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(async () => []),
      } as any,
      shiftRepo: {
        create: vi.fn(),
        getActive: vi.fn(),
      } as any,
      locationCheck: {
        belongsToPhysician: vi.fn(async () => true),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
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
  await testApp.register(scheduleRoutes, { deps: createStubScheduleDeps() });

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
// Route specs — all 10 new Phase 9 endpoints
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';
const DUMMY_UUID_2 = '00000000-0000-0000-0000-000000000002';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const V2_ROUTES: RouteSpec[] = [
  // ---- Shift extension endpoints (5) ----
  {
    method: 'GET',
    url: `/api/v1/shifts/${DUMMY_UUID}`,
    description: 'Get shift details',
  },
  {
    method: 'POST',
    url: '/api/v1/shifts/confirm-inferred',
    payload: { schedule_id: DUMMY_UUID },
    description: 'Confirm inferred shift',
  },
  {
    method: 'POST',
    url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
    payload: {
      phn: '123456789',
      phn_capture_method: 'MANUAL',
      phn_is_partial: false,
      health_service_code: '03.04A',
      encounter_timestamp: '2026-02-19T10:00:00Z',
    },
    description: 'Log encounter in shift',
  },
  {
    method: 'GET',
    url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
    description: 'List shift encounters',
  },
  {
    method: 'DELETE',
    url: `/api/v1/shifts/${DUMMY_UUID}/encounters/${DUMMY_UUID_2}`,
    description: 'Delete encounter from shift',
  },

  // ---- Schedule routes (5) ----
  {
    method: 'GET',
    url: '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28',
    description: 'Get schedule calendar',
  },
  {
    method: 'GET',
    url: '/api/v1/mobile/schedules',
    description: 'List schedules',
  },
  {
    method: 'POST',
    url: '/api/v1/mobile/schedules',
    payload: {
      location_id: DUMMY_UUID,
      name: 'Monday AM',
      rrule: 'FREQ=WEEKLY;BYDAY=MO',
      shift_start_time: '08:00',
      shift_duration_minutes: 480,
    },
    description: 'Create schedule',
  },
  {
    method: 'PUT',
    url: `/api/v1/mobile/schedules/${DUMMY_UUID}`,
    payload: { name: 'Updated' },
    description: 'Update schedule',
  },
  {
    method: 'DELETE',
    url: `/api/v1/mobile/schedules/${DUMMY_UUID}`,
    description: 'Delete schedule',
  },
];

// ---------------------------------------------------------------------------
// Assertion: exactly 10 new routes
// ---------------------------------------------------------------------------

if (V2_ROUTES.length !== 10) {
  throw new Error(
    `Expected 10 V2 routes but found ${V2_ROUTES.length}. ` +
      'Update the route specs to match the registered V2 mobile routes.',
  );
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile V2 Authentication Enforcement (Security)', () => {
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
  // 1. No Cookie — each route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of V2_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 without session cookie`, async () => {
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
  // 2. Expired/Revoked Cookie — each route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of V2_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with expired session`, async () => {
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
  // 3. Tampered Cookie — each route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of V2_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with tampered cookie`, async () => {
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
  // 4. Empty cookie value — returns 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of V2_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with empty cookie value`, async () => {
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
  // 5. Wrong cookie name — returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401 on shift detail', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/shifts/${DUMMY_UUID}`,
        headers: { cookie: `token=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401 on schedules', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/schedules',
        headers: { cookie: `auth=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401 on encounters', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
        headers: { cookie: `sid=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // 6. Sanity: valid session cookie is accepted (confirms test setup)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/shifts/:id returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/shifts/${DUMMY_UUID}`,
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/mobile/schedules returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/schedules',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/shifts/:id/encounters returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 7. 401 response body must not leak V2 data
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
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
        url: '/api/v1/shifts/confirm-inferred',
        payload: { schedule_id: DUMMY_UUID },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not leak encounter, schedule, or PHN data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('encounter');
      expect(rawBody).not.toContain('schedule');
      expect(rawBody).not.toContain('rrule');
      expect(rawBody).not.toContain('phn');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/shifts/${DUMMY_UUID}/encounters`,
        payload: {
          phn: '123456789',
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
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
