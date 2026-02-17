import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { referenceRoutes } from '../../../src/domains/reference/reference.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  role: string;
  subscriptionStatus: string;
}

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

let users: MockUser[] = [];
let sessions: MockSession[] = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: '44444444-0000-0000-0000-000000000001' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub reference repository (not exercised in authn tests)
// ---------------------------------------------------------------------------

function createStubReferenceRepo() {
  return {
    findActiveVersion: vi.fn(async () => undefined),
    findVersionByDate: vi.fn(async () => undefined),
    findVersionById: vi.fn(async () => undefined),
    listVersions: vi.fn(async () => []),
    createVersion: vi.fn(async () => ({})),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),
    searchHscCodes: vi.fn(async () => []),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),
    searchDiCodes: vi.fn(async () => []),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),
    getModifiersForHsc: vi.fn(async () => []),
    getModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),
    listFunctionalCentres: vi.fn(async () => []),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    getExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
    getRrnpCommunity: vi.fn(async () => undefined),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    getPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    listHolidays: vi.fn(async () => []),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async () => ({})),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),
    findGoverningRules: vi.fn(async () => []),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    createStagingEntry: vi.fn(async () => ({})),
    findStagingEntry: vi.fn(async () => undefined),
    deleteStagingEntry: vi.fn(async () => {}),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Expired session
// ---------------------------------------------------------------------------

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = '55555555-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Tampered cookie helper
// ---------------------------------------------------------------------------

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

// ---------------------------------------------------------------------------
// Authenticated routes to test
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// User-facing search/lookup routes
// NOTE: URLs must pass Fastify schema validation (params, querystring, body)
// because schema validation runs BEFORE preHandler auth hooks in Fastify.
const USER_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/hsc/search?q=03.01', description: 'HSC search' },
  { method: 'GET', url: '/api/v1/ref/hsc/favourites', description: 'HSC favourites' },
  { method: 'GET', url: '/api/v1/ref/hsc/03.01A', description: 'HSC detail' },
  { method: 'GET', url: '/api/v1/ref/di/search?q=250', description: 'DI search' },
  { method: 'GET', url: '/api/v1/ref/di/250', description: 'DI detail' },
  { method: 'GET', url: '/api/v1/ref/modifiers', description: 'Modifier list' },
  { method: 'GET', url: '/api/v1/ref/modifiers/ANAE', description: 'Modifier detail' },
  { method: 'GET', url: '/api/v1/ref/functional-centres', description: 'Functional centres' },
  { method: 'GET', url: '/api/v1/ref/explanatory-codes/AA', description: 'Explanatory code' },
  { method: 'GET', url: `/api/v1/ref/rrnp/${DUMMY_UUID}`, description: 'RRNP lookup' },
  { method: 'GET', url: '/api/v1/ref/pcpcm/03.01A', description: 'PCPCM basket' },
  { method: 'GET', url: '/api/v1/ref/holidays?year=2026', description: 'Holiday list' },
  { method: 'GET', url: '/api/v1/ref/holidays/check?date=2026-01-01', description: 'Holiday check' },
];

// Internal validation routes
const INTERNAL_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/rules/validate-context?hsc=03.01A&date=2026-01-01', description: 'Validate context' },
  { method: 'POST', url: '/api/v1/ref/rules/evaluate-batch', payload: { claims: [{ hsc_codes: ['03.01A'], date_of_service: '2026-01-01' }] }, description: 'Evaluate batch' },
  { method: 'GET', url: '/api/v1/ref/rules/RULE001', description: 'Rule detail' },
  { method: 'GET', url: '/api/v1/ref/somb/version?date=2026-01-01', description: 'SOMB version' },
];

// Change summary routes
const CHANGE_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/changes', description: 'Change summary list' },
  { method: 'GET', url: `/api/v1/ref/changes/${DUMMY_UUID}/detail`, description: 'Change detail' },
  { method: 'GET', url: `/api/v1/ref/changes/${DUMMY_UUID}/physician-impact`, description: 'Physician impact' },
];

// Admin routes — dataset param must match ReferenceDataSet enum (uppercase)
const ADMIN_ROUTES: RouteSpec[] = [
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'SOMB upload' },
  { method: 'GET', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/diff`, description: 'Staging diff' },
  { method: 'POST', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`, payload: { version_label: 'v1', effective_from: '2026-03-01', change_summary: 'test' }, description: 'Publish staging' },
  { method: 'DELETE', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}`, description: 'Discard staging' },
  { method: 'GET', url: '/api/v1/admin/ref/SOMB/versions', description: 'Version list' },
  { method: 'POST', url: '/api/v1/admin/ref/holidays', payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' }, description: 'Create holiday' },
  { method: 'PUT', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, payload: { name: 'Updated' }, description: 'Update holiday' },
  { method: 'DELETE', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, description: 'Delete holiday' },
  { method: 'POST', url: '/api/v1/admin/ref/rules/RULE001/dry-run', payload: { updated_rule_logic: {} }, description: 'Dry-run rule' },
];

// All routes combined
const ALL_ROUTES: RouteSpec[] = [
  ...USER_ROUTES,
  ...INTERNAL_ROUTES,
  ...CHANGE_ROUTES,
  ...ADMIN_ROUTES,
];

// Subset of routes for expired-cookie and tampered-cookie tests (per task spec)
const EXPIRED_COOKIE_ROUTES: RouteSpec[] = [
  // User-facing
  { method: 'GET', url: '/api/v1/ref/hsc/search?q=03.01', description: 'HSC search' },
  { method: 'GET', url: '/api/v1/ref/hsc/favourites', description: 'HSC favourites' },
  { method: 'GET', url: '/api/v1/ref/hsc/03.01A', description: 'HSC detail' },
  { method: 'GET', url: '/api/v1/ref/di/search?q=250', description: 'DI search' },
  { method: 'GET', url: '/api/v1/ref/modifiers', description: 'Modifier list' },
  { method: 'GET', url: '/api/v1/ref/modifiers/ANAE', description: 'Modifier detail' },
  { method: 'GET', url: '/api/v1/ref/holidays?year=2026', description: 'Holiday list' },
  { method: 'GET', url: '/api/v1/ref/holidays/check?date=2026-01-01', description: 'Holiday check' },
  // Internal validation
  { method: 'GET', url: '/api/v1/ref/rules/validate-context?hsc=03.01A&date=2026-01-01', description: 'Validate context' },
  { method: 'POST', url: '/api/v1/ref/rules/evaluate-batch', payload: { claims: [{ hsc_codes: ['03.01A'], date_of_service: '2026-01-01' }] }, description: 'Evaluate batch' },
  // Change summary
  { method: 'GET', url: '/api/v1/ref/changes', description: 'Change summary list' },
  // Admin
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'SOMB upload' },
];

const TAMPERED_COOKIE_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/hsc/search?q=03.01', description: 'HSC search' },
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'SOMB upload' },
];

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: createStubReferenceRepo(),
      auditLog: createMockAuditRepo(),
      eventEmitter: createMockEvents(),
    },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
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

  await testApp.register(referenceRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function seedValidSession() {
  users = [];
  sessions = [];

  users.push({
    userId: FIXED_USER_ID,
    email: 'physician@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });

  sessions.push({
    sessionId: FIXED_SESSION_ID,
    userId: FIXED_USER_ID,
    tokenHash: FIXED_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Expired (revoked) session
  sessions.push({
    sessionId: EXPIRED_SESSION_ID,
    userId: FIXED_USER_ID,
    tokenHash: EXPIRED_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
    lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    revoked: true,
    revokedReason: 'expired_absolute',
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedValidSession();
  });

  // =========================================================================
  // No Cookie — each route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of ALL_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 without session cookie (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        // No data leakage — must not contain data field
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired Cookie — returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of EXPIRED_COOKIE_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with expired session (${route.description})`, async () => {
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
  // Tampered Cookie — returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of TAMPERED_COOKIE_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with tampered cookie (${route.description})`, async () => {
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
    for (const route of ALL_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — returns 401 with empty cookie value (${route.description})`, async () => {
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
  // Verify valid session works (sanity check)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/ref/holidays returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/changes returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak information
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/modifiers',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not contain reference data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/03.01A',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('hscCode');
      expect(rawBody).not.toContain('health_service_code');
      expect(rawBody).not.toContain('modifier');
      expect(rawBody).not.toContain('governing_rule');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      // Should only have code and message — no extra fields
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('401 response does not set a session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
      });

      expect(res.statusCode).toBe(401);
      const setCookie = res.headers['set-cookie'];
      expect(setCookie).toBeUndefined();
    });
  });

  // =========================================================================
  // Wrong cookie name — returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });
  });
});
