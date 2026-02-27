// ============================================================================
// Domain 7: Intelligence Extensions — Authentication Enforcement (Security)
// Verifies the 4 extension admin endpoints return 401 without valid session.
// 4 routes x 4 auth failure modes = 16 test cases.
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
import { intelRoutes } from '../../../src/domains/intel/intel.routes.js';
import { type IntelHandlerDeps } from '../../../src/domains/intel/intel.handlers.js';
import { type AnalyseDeps, type LifecycleDeps, type LearningLoopDeps, type SombChangeDeps } from '../../../src/domains/intel/intel.service.js';
import type { IntelRepository } from '../../../src/domains/intel/intel.repository.js';

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

function createStubIntelHandlerDeps(): IntelHandlerDeps {
  const stubAnalyseDeps: AnalyseDeps = {
    claimContextDeps: {
      getClaim: vi.fn(),
      getAhcipDetails: vi.fn(),
      getWcbDetails: vi.fn(),
      getPatientDemographics: vi.fn(),
      getProvider: vi.fn(),
      getDefaultLocation: vi.fn(),
      getHscCode: vi.fn(),
      getModifierDefinitions: vi.fn(),
      getDiCode: vi.fn(),
      getReferenceSet: vi.fn(),
      getCrossClaimCount: vi.fn(),
      getCrossClaimSum: vi.fn(),
      getCrossClaimExists: vi.fn(),
    },
    tier1Deps: {
      getActiveRulesForClaim: vi.fn(),
      getProviderLearningForRules: vi.fn(),
      incrementShown: vi.fn(),
      appendSuggestionEvent: vi.fn(),
    },
    tier2Deps: {
      buildPrompt: vi.fn(),
      callLlm: vi.fn(),
      parseResponse: vi.fn(),
      appendSuggestionEvent: vi.fn(),
    },
    storeSuggestions: vi.fn(),
    notifyTier2Complete: vi.fn(),
  };

  const stubLifecycleDeps: LifecycleDeps = {
    getClaimSuggestions: vi.fn(),
    updateClaimSuggestions: vi.fn(),
    applyClaimChanges: vi.fn(),
    revalidateClaim: vi.fn(),
    appendSuggestionEvent: vi.fn(),
    recordAcceptance: vi.fn(),
    recordDismissal: vi.fn(),
  };

  const stubLearningLoopDeps: LearningLoopDeps = {
    getProviderLearning: vi.fn(),
    unsuppressRule: vi.fn(),
    processRejection: vi.fn(),
    recalculateAllCohorts: vi.fn(),
    deleteSmallCohorts: vi.fn(),
  };

  const stubSombChangeDeps: SombChangeDeps = {
    getRulesByVersion: vi.fn(),
    getAffectedProviders: vi.fn(),
    generateImpactReport: vi.fn(),
  };

  const stubRepo: IntelRepository = {
    listRules: vi.fn(),
    getRule: vi.fn(),
    createRule: vi.fn(),
    updateRule: vi.fn(),
    activateRule: vi.fn(),
    getRuleStats: vi.fn(),
    getLearningStateSummary: vi.fn(),
    findClaimIdBySuggestionId: vi.fn(),
    getActiveRulesForClaim: vi.fn(),
    getProviderLearningForRules: vi.fn(),
    incrementShown: vi.fn(),
    appendSuggestionEvent: vi.fn(),
    getClaimSuggestions: vi.fn(),
    updateClaimSuggestions: vi.fn(),
    recordAcceptance: vi.fn(),
    recordDismissal: vi.fn(),
    unsuppressRule: vi.fn(),
    listCohorts: vi.fn(),
    upsertCohort: vi.fn(),
    deleteSmallCohorts: vi.fn(),
    getProvidersBySpecialty: vi.fn(),
    getProviderLearningByRule: vi.fn(),
    listSuggestionEvents: vi.fn(),
  } as unknown as IntelRepository;

  return {
    analyseDeps: stubAnalyseDeps,
    lifecycleDeps: stubLifecycleDeps,
    learningLoopDeps: stubLearningLoopDeps,
    sombChangeDeps: stubSombChangeDeps,
    repo: stubRepo,
    auditLog: vi.fn(async () => {}),
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

  await testApp.register(intelRoutes, { deps: createStubIntelHandlerDeps() });
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
// Route specs — the 4 extension admin endpoints
// ---------------------------------------------------------------------------

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const EXTENSION_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/intelligence/somb-change-analysis',
    payload: { old_version: '2025-12', new_version: '2026-01' },
    description: 'SOMB change analysis (admin)',
  },
  {
    method: 'POST',
    url: '/api/v1/intelligence/cohorts/recalculate',
    description: 'Recalculate cohorts (admin)',
  },
  {
    method: 'GET',
    url: `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`,
    description: 'Get rule stats (admin)',
  },
  {
    method: 'PUT',
    url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
    payload: { is_active: true },
    description: 'Activate rule (admin)',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Extensions Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Seed a valid admin user + active session (for sanity checks)
    users.push({
      userId: VALID_USER_ID,
      role: 'ADMIN',
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
  // No Cookie — each extension route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 without session cookie`, async () => {
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
  // Expired/Revoked Cookie — each extension route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with expired session`, async () => {
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
  // Tampered Cookie — each extension route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with tampered cookie`, async () => {
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
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with empty cookie value`, async () => {
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
  // Sanity: valid admin session cookie is accepted
  // =========================================================================

  describe('Sanity: valid admin session cookie is accepted', () => {
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns non-401 with valid admin session`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${VALID_SESSION_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).not.toBe(401);
      });
    }
  });

  // =========================================================================
  // 401 response body must not leak intelligence data
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`,
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
        url: '/api/v1/intelligence/somb-change-analysis',
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
    });

    it('401 response does not leak rule stats or cohort data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('cohort');
      expect(rawBody).not.toContain('specialty');
      expect(rawBody).not.toContain('acceptance');
      expect(rawBody).not.toContain('rule');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        payload: { is_active: true },
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
