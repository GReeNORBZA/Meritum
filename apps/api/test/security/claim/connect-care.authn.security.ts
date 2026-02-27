// ============================================================================
// Connect Care Import — Authentication Enforcement (Security)
// Verifies every CC import + reconciliation endpoint returns 401 without
// valid session. 10 routes x 4 auth failure modes + sanity + leakage checks.
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
// Mock otplib
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
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
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
// Mock session repository
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
// Stub claim deps (requests should never reach handlers)
// ---------------------------------------------------------------------------

function createStubHandlerDeps(): ClaimHandlerDeps {
  return {
    serviceDeps: {
      repo: {
        createClaim: vi.fn(async () => ({})),
        findClaimById: vi.fn(async () => undefined),
        updateClaim: vi.fn(async () => ({})),
        softDeleteClaim: vi.fn(async () => false),
        listClaims: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        countClaimsByState: vi.fn(async () => []),
        findClaimsApproachingDeadline: vi.fn(async () => []),
        transitionState: vi.fn(async () => ({})),
        classifyClaim: vi.fn(async () => ({})),
        updateValidationResult: vi.fn(async () => ({})),
        updateAiSuggestions: vi.fn(async () => ({})),
        updateDuplicateAlert: vi.fn(async () => ({})),
        updateFlags: vi.fn(async () => ({})),
        createImportBatch: vi.fn(async () => ({})),
        findImportBatchById: vi.fn(async () => undefined),
        updateImportBatchStatus: vi.fn(async () => ({})),
        findDuplicateImportByHash: vi.fn(async () => undefined),
        listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsForBatchAssembly: vi.fn(async () => []),
        bulkTransitionState: vi.fn(async () => []),
        createTemplate: vi.fn(async () => ({})),
        findTemplateById: vi.fn(async () => undefined),
        updateTemplate: vi.fn(async () => ({})),
        deleteTemplate: vi.fn(async () => {}),
        listTemplates: vi.fn(async () => []),
        createShift: vi.fn(async () => ({})),
        findShiftById: vi.fn(async () => undefined),
        updateShiftStatus: vi.fn(async () => ({})),
        updateShiftTimes: vi.fn(async () => ({})),
        incrementEncounterCount: vi.fn(async () => ({})),
        listShifts: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsByShift: vi.fn(async () => []),
        createExportRecord: vi.fn(async () => ({})),
        findExportById: vi.fn(async () => undefined),
        updateExportStatus: vi.fn(async () => ({})),
        appendClaimAudit: vi.fn(async () => ({})),
        getClaimAuditHistory: vi.fn(async () => []),
        getClaimAuditHistoryPaginated: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
      } as any,
      providerCheck: {
        isActive: vi.fn(async () => true),
        getRegistrationDate: vi.fn(async () => null),
      },
      patientCheck: { exists: vi.fn(async () => true) },
      pathwayValidators: {},
      referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
      notificationEmitter: { emit: vi.fn(async () => {}) },
      submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
      afterHoursPremiumCalculators: {},
      explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const sessionDeps = {
    sessionRepo: createMockSessionRepo(),
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(claimRoutes, { deps: createStubHandlerDeps() });
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
// Authenticated routes: Connect Care Import + Reconciliation
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const CC_ROUTES: RouteSpec[] = [
  // Connect Care Import (5 endpoints)
  {
    method: 'POST',
    url: '/api/v1/claims/connect-care/import',
    payload: { spec_version: '1.0' },
    description: 'Upload CC import',
  },
  {
    method: 'GET',
    url: '/api/v1/claims/connect-care/import/history',
    description: 'List CC import history',
  },
  {
    method: 'GET',
    url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}`,
    description: 'Get CC import batch',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}/confirm`,
    payload: { action: 'CONFIRMED' },
    description: 'Confirm CC import',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}/cancel`,
    description: 'Cancel CC import',
  },

  // Reconciliation (5 endpoints)
  {
    method: 'POST',
    url: '/api/v1/claims/connect-care/reconcile',
    payload: { batch_id: DUMMY_UUID },
    description: 'Trigger reconciliation',
  },
  {
    method: 'GET',
    url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}`,
    description: 'Get reconciliation result',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/confirm`,
    description: 'Confirm reconciliation',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-time`,
    payload: { claim_id: DUMMY_UUID, inferred_service_time: '2026-02-16T10:30:00.000Z' },
    description: 'Resolve unmatched time',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-partial`,
    payload: { encounter_id: DUMMY_UUID, claim_id: DUMMY_UUID },
    description: 'Resolve partial PHN',
  },
];

// ============================================================================
// Test Suite
// ============================================================================

describe('Connect Care Import — Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];

    users.push({
      userId: VALID_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'TRIAL',
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
  // No Cookie — 401
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of CC_ROUTES) {
      it(`${route.method} ${route.url} — 401 without session cookie`, async () => {
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
  // Expired Cookie — 401
  // =========================================================================

  describe('Requests with expired/revoked session return 401', () => {
    for (const route of CC_ROUTES) {
      it(`${route.method} ${route.url} — 401 with expired session`, async () => {
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
  // Tampered Cookie — 401
  // =========================================================================

  describe('Requests with tampered cookie return 401', () => {
    for (const route of CC_ROUTES) {
      it(`${route.method} ${route.url} — 401 with tampered cookie`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${createTamperedCookie()}` },
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
  // Empty Cookie — 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of CC_ROUTES) {
      it(`${route.method} ${route.url} — 401 with empty cookie`, async () => {
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
  // Wrong cookie name — 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/connect-care/import',
        headers: { cookie: `token=${VALID_SESSION_TOKEN}` },
        payload: { spec_version: '1.0' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/connect-care/import/history',
        headers: { cookie: `auth=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session is accepted (not 401)
  // =========================================================================

  describe('Sanity: valid session is accepted', () => {
    it('GET /api/v1/claims/connect-care/import/history returns non-401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/connect-care/import/history',
        headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response does not leak information
  // =========================================================================

  describe('401 responses do not leak information', () => {
    it('no stack trace in 401 response', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/connect-care/import',
        payload: { file_name: 'test.csv', raw_content: 'a,b,c', spec_version: '1.0' },
      });
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('stack');
      expect(res.body).not.toContain('postgres');
      expect(res.body).not.toContain('session_id');
    });
  });
});
