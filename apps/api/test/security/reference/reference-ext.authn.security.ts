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
    findVersionForDate: vi.fn(async () => undefined),
    findVersionByDate: vi.fn(async () => undefined),
    findVersionById: vi.fn(async () => undefined),
    listVersions: vi.fn(async () => []),
    createVersion: vi.fn(async () => ({})),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),
    listHscByVersion: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),
    findModifiersForHsc: vi.fn(async () => []),
    getModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    getModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),
    listFunctionalCentres: vi.fn(async () => []),
    findFunctionalCentre: vi.fn(async () => undefined),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    findExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunity: vi.fn(async () => undefined),
    listRrnpCommunities: vi.fn(async () => []),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    listHolidaysByYear: vi.fn(async () => []),
    listHolidays: vi.fn(async () => []),
    isHoliday: vi.fn(async () => false),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async () => ({})),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async () => undefined),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    listRulesByCategory: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),
    createStagingRecord: vi.fn(async () => ({})),
    createStagingEntry: vi.fn(async () => ({})),
    findStagingById: vi.fn(async () => undefined),
    findStagingEntry: vi.fn(async () => undefined),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),
    deleteStagingEntry: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),
    // Extension repo methods
    getIcdCrosswalkByIcd10: vi.fn(async () => []),
    searchIcdCrosswalk: vi.fn(async () => []),
    bulkInsertIcdCrosswalk: vi.fn(async () => {}),
    searchProviderRegistry: vi.fn(async () => []),
    getProviderByCpsa: vi.fn(async () => undefined),
    bulkUpsertProviderRegistry: vi.fn(async () => {}),
    listBillingGuidance: vi.fn(async () => []),
    searchBillingGuidance: vi.fn(async () => []),
    getBillingGuidanceById: vi.fn(async () => undefined),
    listProvincialPhnFormats: vi.fn(async () => []),
    getReciprocalRules: vi.fn(async () => []),
    listAnesthesiaRules: vi.fn(async () => []),
    getAnesthesiaRuleByScenario: vi.fn(async () => undefined),
    getBundlingRuleForPair: vi.fn(async () => undefined),
    checkBundlingConflicts: vi.fn(async () => []),
    listJustificationTemplates: vi.fn(async () => []),
    getJustificationTemplate: vi.fn(async () => undefined),
    // WCB
    searchWcbCodes: vi.fn(async () => []),
    findWcbByCode: vi.fn(async () => undefined),
    bulkInsertWcbCodes: vi.fn(async () => {}),
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
// Authenticated routes to test — extension endpoints only
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// -------------------------------------------------------------------------
// Extension user-facing read endpoints (CLAIM_VIEW permission)
// -------------------------------------------------------------------------

const EXT_USER_ROUTES: RouteSpec[] = [
  // ICD Crosswalk (FRD CC-001)
  { method: 'GET', url: '/api/v1/ref/icd-crosswalk?q=flu', description: 'ICD crosswalk search' },
  { method: 'GET', url: '/api/v1/ref/icd-crosswalk/J09', description: 'ICD crosswalk detail' },
  // Provider Registry (FRD MVPADD-001 B1)
  { method: 'GET', url: '/api/v1/ref/providers/search?q=Smith', description: 'Provider registry search' },
  { method: 'GET', url: '/api/v1/ref/providers/12345', description: 'Provider registry detail' },
  // Billing Guidance (FRD MVPADD-001 B6)
  { method: 'GET', url: '/api/v1/ref/guidance', description: 'Billing guidance list' },
  { method: 'GET', url: `/api/v1/ref/guidance/${DUMMY_UUID}`, description: 'Billing guidance detail' },
  // Provincial PHN Formats (FRD MVPADD-001 B8)
  { method: 'GET', url: '/api/v1/ref/provincial-phn-formats', description: 'Provincial PHN formats' },
  // Reciprocal Billing (FRD MVPADD-001 B8)
  { method: 'GET', url: '/api/v1/ref/reciprocal-rules/AB', description: 'Reciprocal billing rules' },
  // Anesthesia Rules (FRD MVPADD-001 B7)
  { method: 'GET', url: '/api/v1/ref/anesthesia-rules', description: 'Anesthesia rules list' },
  { method: 'GET', url: '/api/v1/ref/anesthesia-rules/ANES01', description: 'Anesthesia rule detail' },
  { method: 'POST', url: '/api/v1/ref/anesthesia-rules/calculate', payload: { scenario_code: 'ANES01', time_minutes: 60 }, description: 'Anesthesia calculate' },
  // Bundling Rules (FRD MVPADD-001 B9)
  { method: 'GET', url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J', description: 'Bundling pair lookup' },
  { method: 'POST', url: '/api/v1/ref/bundling-rules/check', payload: { codes: ['03.01A', '03.04J'] }, description: 'Bundling conflict check' },
  // Justification Templates (FRD MVPADD-001 B11)
  { method: 'GET', url: '/api/v1/ref/justification-templates', description: 'Justification templates list' },
  { method: 'GET', url: `/api/v1/ref/justification-templates/${DUMMY_UUID}`, description: 'Justification template detail' },
];

// -------------------------------------------------------------------------
// Extension admin endpoints
// -------------------------------------------------------------------------

const EXT_ADMIN_ROUTES: RouteSpec[] = [
  { method: 'POST', url: '/api/v1/admin/ref/holidays', payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' }, description: 'Create holiday' },
  { method: 'PUT', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, payload: { name: 'Updated' }, description: 'Update holiday' },
  { method: 'DELETE', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, description: 'Delete holiday' },
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'Dataset upload' },
  { method: 'GET', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/diff`, description: 'Staging diff' },
  { method: 'POST', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`, payload: { version_label: 'v1', effective_from: '2026-03-01', change_summary: 'test' }, description: 'Publish staging' },
  { method: 'DELETE', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}`, description: 'Discard staging' },
  { method: 'GET', url: '/api/v1/admin/ref/SOMB/versions', description: 'Version list' },
  { method: 'POST', url: '/api/v1/admin/ref/rules/RULE001/dry-run', payload: { updated_rule_logic: {} }, description: 'Dry-run rule' },
];

// All extension routes combined
const ALL_EXT_ROUTES: RouteSpec[] = [
  ...EXT_USER_ROUTES,
  ...EXT_ADMIN_ROUTES,
];

// Representative subset for expired/tampered cookie tests (covers each category)
const EXPIRED_COOKIE_ROUTES: RouteSpec[] = [
  // ICD Crosswalk
  { method: 'GET', url: '/api/v1/ref/icd-crosswalk?q=flu', description: 'ICD crosswalk search' },
  { method: 'GET', url: '/api/v1/ref/icd-crosswalk/J09', description: 'ICD crosswalk detail' },
  // Provider Registry
  { method: 'GET', url: '/api/v1/ref/providers/search?q=Smith', description: 'Provider registry search' },
  { method: 'GET', url: '/api/v1/ref/providers/12345', description: 'Provider registry detail' },
  // Billing Guidance
  { method: 'GET', url: '/api/v1/ref/guidance', description: 'Billing guidance list' },
  { method: 'GET', url: `/api/v1/ref/guidance/${DUMMY_UUID}`, description: 'Billing guidance detail' },
  // Provincial / Reciprocal
  { method: 'GET', url: '/api/v1/ref/provincial-phn-formats', description: 'Provincial PHN formats' },
  { method: 'GET', url: '/api/v1/ref/reciprocal-rules/AB', description: 'Reciprocal billing rules' },
  // Anesthesia
  { method: 'GET', url: '/api/v1/ref/anesthesia-rules', description: 'Anesthesia rules list' },
  { method: 'POST', url: '/api/v1/ref/anesthesia-rules/calculate', payload: { scenario_code: 'ANES01', time_minutes: 60 }, description: 'Anesthesia calculate' },
  // Bundling
  { method: 'POST', url: '/api/v1/ref/bundling-rules/check', payload: { codes: ['03.01A', '03.04J'] }, description: 'Bundling conflict check' },
  // Justification
  { method: 'GET', url: '/api/v1/ref/justification-templates', description: 'Justification templates list' },
  // Admin
  { method: 'POST', url: '/api/v1/admin/ref/holidays', payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' }, description: 'Create holiday (admin)' },
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'Dataset upload (admin)' },
  { method: 'POST', url: '/api/v1/admin/ref/rules/RULE001/dry-run', payload: { updated_rule_logic: {} }, description: 'Dry-run rule (admin)' },
];

const TAMPERED_COOKIE_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/icd-crosswalk?q=flu', description: 'ICD crosswalk search' },
  { method: 'GET', url: '/api/v1/ref/providers/search?q=Smith', description: 'Provider registry search' },
  { method: 'GET', url: '/api/v1/ref/guidance', description: 'Billing guidance list' },
  { method: 'GET', url: '/api/v1/ref/anesthesia-rules', description: 'Anesthesia rules list' },
  { method: 'POST', url: '/api/v1/ref/bundling-rules/check', payload: { codes: ['03.01A', '03.04J'] }, description: 'Bundling conflict check' },
  { method: 'GET', url: '/api/v1/ref/justification-templates', description: 'Justification templates list' },
  { method: 'POST', url: '/api/v1/admin/ref/holidays', payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' }, description: 'Create holiday (admin)' },
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'Dataset upload (admin)' },
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

describe('Reference Data Extensions Authentication Enforcement (Security)', () => {
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
  // No Cookie -- each extension route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of ALL_EXT_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} -- returns 401 without session cookie (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        // No data leakage -- must not contain data field
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired Cookie -- returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of EXPIRED_COOKIE_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} -- returns 401 with expired session (${route.description})`, async () => {
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
  // Tampered Cookie -- returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of TAMPERED_COOKIE_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} -- returns 401 with tampered cookie (${route.description})`, async () => {
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
  // Empty cookie value -- returns 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of ALL_EXT_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} -- returns 401 with empty cookie value (${route.description})`, async () => {
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
  // Wrong cookie name -- returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401 on ICD crosswalk', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401 on provider search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401 on guidance list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: `sid=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "jwt" instead of "session" returns 401 on anesthesia rules', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: `jwt=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "access_token" instead of "session" returns 401 on admin endpoint', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: `access_token=${FIXED_SESSION_TOKEN}` },
        payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "SESSION" (uppercase) instead of "session" returns 401 on bundling check', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: `SESSION=${FIXED_SESSION_TOKEN}` },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/ref/icd-crosswalk returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/providers/search returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/guidance returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/provincial-phn-formats returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/anesthesia-rules returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/ref/anesthesia-rules/calculate returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/ref/bundling-rules/check returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ref/justification-templates returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 responses must not leak information
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response on ICD crosswalk does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response on provider search does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response on guidance does not contain reference data', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('guidance');
      expect(rawBody).not.toContain('provider');
      expect(rawBody).not.toContain('anesthesia');
      expect(rawBody).not.toContain('bundling');
    });

    it('401 response on anesthesia calculate does not contain calculation results', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('base_units');
      expect(rawBody).not.toContain('calculated_fee');
      expect(rawBody).not.toContain('time_units');
    });

    it('401 response on bundling check does not leak rule data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('conflict');
      expect(rawBody).not.toContain('bundling');
      expect(rawBody).not.toContain('code_a');
      expect(rawBody).not.toContain('code_b');
    });

    it('401 response has consistent error shape across extension endpoints', async () => {
      const endpoints = [
        '/api/v1/ref/icd-crosswalk?q=flu',
        '/api/v1/ref/providers/search?q=Smith',
        '/api/v1/ref/guidance',
        '/api/v1/ref/provincial-phn-formats',
        '/api/v1/ref/anesthesia-rules',
        '/api/v1/ref/justification-templates',
      ];

      for (const url of endpoints) {
        const res = await app.inject({ method: 'GET', url });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(Object.keys(body)).toEqual(['error']);
        expect(body.error).toHaveProperty('code');
        expect(body.error).toHaveProperty('message');
        expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
      }
    });

    it('401 response does not set a session cookie on extension endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
      });

      expect(res.statusCode).toBe(401);
      const setCookie = res.headers['set-cookie'];
      expect(setCookie).toBeUndefined();
    });

    it('401 response on admin extension endpoint does not set a session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      expect(res.statusCode).toBe(401);
      const setCookie = res.headers['set-cookie'];
      expect(setCookie).toBeUndefined();
    });
  });
});
