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
// Fixed test users/sessions — one per role
// ---------------------------------------------------------------------------

// Physician user (TRIAL subscription)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000012';

// Delegate with CLAIM_VIEW permission
const DELEGATE_CV_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CV_SESSION_TOKEN_HASH = hashToken(DELEGATE_CV_SESSION_TOKEN);
const DELEGATE_CV_USER_ID = 'bbbb0000-0000-0000-0000-000000000001';
const DELEGATE_CV_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000011';

// Delegate without CLAIM_VIEW permission (only PATIENT_VIEW)
const DELEGATE_NO_CV_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NO_CV_SESSION_TOKEN_HASH = hashToken(DELEGATE_NO_CV_SESSION_TOKEN);
const DELEGATE_NO_CV_USER_ID = 'bbbb0000-0000-0000-0000-000000000002';
const DELEGATE_NO_CV_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000012';

// Suspended physician
const SUSPENDED_SESSION_TOKEN = randomBytes(32).toString('hex');
const SUSPENDED_SESSION_TOKEN_HASH = hashToken(SUSPENDED_SESSION_TOKEN);
const SUSPENDED_USER_ID = 'cccc0000-0000-0000-0000-000000000001';
const SUSPENDED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000011';

// Cancelled physician
const CANCELLED_SESSION_TOKEN = randomBytes(32).toString('hex');
const CANCELLED_SESSION_TOKEN_HASH = hashToken(CANCELLED_SESSION_TOKEN);
const CANCELLED_USER_ID = 'cccc0000-0000-0000-0000-000000000002';
const CANCELLED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000012';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  role: string;
  subscriptionStatus: string;
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
          ...(user.delegateContext ? { delegateContext: user.delegateContext } : {}),
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
// Stub reference repository (not exercised in authz tests)
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
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

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
// Helpers: Seed users and sessions
// ---------------------------------------------------------------------------

function seedAllUsers() {
  users = [];
  sessions = [];

  // Physician (TRIAL, active subscription)
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@meritum.ca',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_VIEW
  users.push({
    userId: DELEGATE_CV_USER_ID,
    email: 'delegate-cv@example.com',
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_CV_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      linkageId: 'dddd0000-0000-0000-0000-000000000001',
    },
  });
  sessions.push({
    sessionId: DELEGATE_CV_SESSION_ID,
    userId: DELEGATE_CV_USER_ID,
    tokenHash: DELEGATE_CV_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate without CLAIM_VIEW
  users.push({
    userId: DELEGATE_NO_CV_USER_ID,
    email: 'delegate-no-cv@example.com',
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_NO_CV_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['PATIENT_VIEW'],
      linkageId: 'dddd0000-0000-0000-0000-000000000002',
    },
  });
  sessions.push({
    sessionId: DELEGATE_NO_CV_SESSION_ID,
    userId: DELEGATE_NO_CV_USER_ID,
    tokenHash: DELEGATE_NO_CV_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Suspended physician
  users.push({
    userId: SUSPENDED_USER_ID,
    email: 'suspended@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'SUSPENDED',
  });
  sessions.push({
    sessionId: SUSPENDED_SESSION_ID,
    userId: SUSPENDED_USER_ID,
    tokenHash: SUSPENDED_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Cancelled physician
  users.push({
    userId: CANCELLED_USER_ID,
    email: 'cancelled@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'CANCELLED',
  });
  sessions.push({
    sessionId: CANCELLED_SESSION_ID,
    userId: CANCELLED_USER_ID,
    tokenHash: CANCELLED_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// Cookie helpers
function physicianCookie(): string { return `session=${PHYSICIAN_SESSION_TOKEN}`; }
function adminCookie(): string { return `session=${ADMIN_SESSION_TOKEN}`; }
function delegateCvCookie(): string { return `session=${DELEGATE_CV_SESSION_TOKEN}`; }
function delegateNoCvCookie(): string { return `session=${DELEGATE_NO_CV_SESSION_TOKEN}`; }
function suspendedCookie(): string { return `session=${SUSPENDED_SESSION_TOKEN}`; }
function cancelledCookie(): string { return `session=${CANCELLED_SESSION_TOKEN}`; }

// ---------------------------------------------------------------------------
// Route specifications
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// Admin routes — require ADMIN role
const ADMIN_ROUTES: RouteSpec[] = [
  { method: 'POST', url: '/api/v1/admin/ref/SOMB/upload', description: 'SOMB upload' },
  { method: 'POST', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`, payload: { version_label: 'v1', effective_from: '2026-03-01', change_summary: 'test' }, description: 'Publish staging' },
  { method: 'DELETE', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}`, description: 'Discard staging' },
  { method: 'GET', url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/diff`, description: 'Staging diff' },
  { method: 'GET', url: '/api/v1/admin/ref/SOMB/versions', description: 'Version list' },
  { method: 'POST', url: '/api/v1/admin/ref/holidays', payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' }, description: 'Create holiday' },
  { method: 'PUT', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, payload: { name: 'Updated' }, description: 'Update holiday' },
  { method: 'DELETE', url: `/api/v1/admin/ref/holidays/${DUMMY_UUID}`, description: 'Delete holiday' },
  { method: 'POST', url: '/api/v1/admin/ref/rules/RULE001/dry-run', payload: { updated_rule_logic: {} }, description: 'Dry-run rule' },
];

// User-facing search/lookup routes
const SEARCH_ROUTES: RouteSpec[] = [
  { method: 'GET', url: '/api/v1/ref/hsc/search?q=03.01', description: 'HSC search' },
  { method: 'GET', url: '/api/v1/ref/di/search?q=250', description: 'DI search' },
  { method: 'GET', url: '/api/v1/ref/modifiers', description: 'Modifier list' },
];

const ALL_USER_ROUTES: RouteSpec[] = [
  ...SEARCH_ROUTES,
  { method: 'GET', url: '/api/v1/ref/hsc/favourites', description: 'HSC favourites' },
  { method: 'GET', url: '/api/v1/ref/hsc/03.01A', description: 'HSC detail' },
  { method: 'GET', url: '/api/v1/ref/di/250', description: 'DI detail' },
  { method: 'GET', url: '/api/v1/ref/modifiers/ANAE', description: 'Modifier detail' },
  { method: 'GET', url: '/api/v1/ref/functional-centres', description: 'Functional centres' },
  { method: 'GET', url: '/api/v1/ref/explanatory-codes/AA', description: 'Explanatory code' },
  { method: 'GET', url: `/api/v1/ref/rrnp/${DUMMY_UUID}`, description: 'RRNP lookup' },
  { method: 'GET', url: '/api/v1/ref/pcpcm/03.01A', description: 'PCPCM basket' },
  { method: 'GET', url: '/api/v1/ref/holidays?year=2026', description: 'Holiday list' },
  { method: 'GET', url: '/api/v1/ref/holidays/check?date=2026-01-01', description: 'Holiday check' },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Authorization & Role Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedAllUsers();
  });

  // =========================================================================
  // Sanity: verify test users authenticate correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: physicianCookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('admin session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate with CLAIM_VIEW authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        headers: { cookie: delegateCvCookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Admin routes reject non-admin users (physician)
  // =========================================================================

  describe('Admin routes reject physician users', () => {
    for (const route of ADMIN_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — physician gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: physicianCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Admin routes reject delegates
  // =========================================================================

  describe('Admin routes reject delegate users', () => {
    for (const route of ADMIN_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — delegate with CLAIM_VIEW gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateCvCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }

    for (const route of ADMIN_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — delegate without CLAIM_VIEW gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateNoCvCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Admin routes accept admin users
  // =========================================================================

  describe('Admin routes accept admin users', () => {
    it('POST /api/v1/admin/ref/SOMB/upload as admin — not 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: { cookie: adminCookie() },
      });
      // May fail with 400/415 (no file uploaded), but should not be 403
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/admin/ref/holidays as admin — not 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Test Holiday', date: '2026-12-25', jurisdiction: 'provincial' },
      });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/admin/ref/SOMB/versions as admin — not 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Delegate with CLAIM_VIEW can access search routes
  // =========================================================================

  describe('Delegate with CLAIM_VIEW can access search/lookup routes', () => {
    for (const route of SEARCH_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — delegate with CLAIM_VIEW is not blocked (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateCvCookie() },
        });
        // Should not be 401 or 403 — delegate with CLAIM_VIEW has access
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
        expect(res.statusCode).not.toBe(402);
      });
    }
  });

  // =========================================================================
  // Delegate without CLAIM_VIEW cannot access search routes
  // =========================================================================

  describe('Delegate without CLAIM_VIEW cannot access search/lookup routes', () => {
    for (const route of ALL_USER_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — delegate without CLAIM_VIEW gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateNoCvCookie() },
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Subscription-gated access: SUSPENDED (read-only)
  // =========================================================================

  describe('SUSPENDED user: read-only access to reference data', () => {
    it('GET /api/v1/ref/hsc/search as SUSPENDED — allowed (200)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01',
        headers: { cookie: suspendedCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ref/hsc/:code as SUSPENDED — allowed', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/03.01A',
        headers: { cookie: suspendedCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ref/holidays as SUSPENDED — allowed', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: suspendedCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ref/di/search as SUSPENDED — allowed', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/di/search?q=250',
        headers: { cookie: suspendedCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ref/modifiers as SUSPENDED — allowed', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/modifiers',
        headers: { cookie: suspendedCookie() },
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(402);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Subscription-gated access: CANCELLED (no access)
  // =========================================================================

  describe('CANCELLED user: no access to reference data routes', () => {
    it('GET /api/v1/ref/hsc/search as CANCELLED — blocked (402)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01',
        headers: { cookie: cancelledCookie() },
      });
      expect(res.statusCode).toBe(402);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');
    });

    it('GET /api/v1/ref/di/search as CANCELLED — blocked (402)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/di/search?q=250',
        headers: { cookie: cancelledCookie() },
      });
      expect(res.statusCode).toBe(402);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');
    });

    it('GET /api/v1/ref/modifiers as CANCELLED — blocked (402)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/modifiers',
        headers: { cookie: cancelledCookie() },
      });
      expect(res.statusCode).toBe(402);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');
    });

    it('GET /api/v1/ref/hsc/:code as CANCELLED — blocked (402)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/03.01A',
        headers: { cookie: cancelledCookie() },
      });
      expect(res.statusCode).toBe(402);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');
    });

    it('GET /api/v1/ref/holidays as CANCELLED — blocked (402)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: cancelledCookie() },
      });
      expect(res.statusCode).toBe(402);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('SUBSCRIPTION_REQUIRED');
    });
  });

  // =========================================================================
  // 403 response shape verification
  // =========================================================================

  describe('403 responses have correct shape and leak no information', () => {
    it('403 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: physicianCookie() },
        payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internal details', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('403 message is generic — does not reveal required role', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: physicianCookie() },
        payload: { name: 'Test', date: '2026-12-25', jurisdiction: 'provincial' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('PHYSICIAN');
      expect(body.error.message).not.toContain('ADMIN');
      expect(body.error.message).not.toContain('DELEGATE');
    });
  });

  // =========================================================================
  // Physician can access all user-facing routes (not blocked by authz)
  // =========================================================================

  describe('Physician can access all user-facing reference routes', () => {
    for (const route of ALL_USER_ROUTES) {
      it(`${route.method} ${route.url.split('?')[0]} — physician is not blocked by role/permission check (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: physicianCookie() },
        });
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
        expect(res.statusCode).not.toBe(402);
      });
    }
  });
});
