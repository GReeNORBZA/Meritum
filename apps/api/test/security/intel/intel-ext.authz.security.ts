// ============================================================================
// Domain 7: Intelligence Extensions — Authorization & Permission Enforcement
// Verifies admin-only extension endpoints return 403 for physician role and
// that physician can still access physician-facing endpoints normally.
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

// Physician user — has AI_COACH_VIEW and AI_COACH_MANAGE but NOT admin
const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Admin user — has all permissions + admin-only access
const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// Delegate with AI_COACH_VIEW + AI_COACH_MANAGE (not admin)
const DELEGATE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_TOKEN_HASH = hashToken(DELEGATE_TOKEN);
const DELEGATE_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';
const PHYSICIAN_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
// Stub handler deps
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
    listRules: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    getRule: vi.fn(),
    createRule: vi.fn(),
    updateRule: vi.fn(),
    activateRule: vi.fn(),
    getRuleStats: vi.fn(),
    getLearningStateSummary: vi.fn(async () => ({
      suppressedCount: 0,
      topCategories: [],
      acceptanceRate: 0,
      totalSuggestions: 0,
    })),
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

function injectAs(token: string, method: 'GET' | 'POST' | 'PUT', url: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${token}` },
    ...(payload ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const VALID_SOMB_CHANGE_PAYLOAD = { old_version: '2025-12', new_version: '2026-01' };
const VALID_ACTIVATE_RULE_PAYLOAD = { is_active: true };

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Extensions Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Physician — full access to AI_COACH_VIEW and AI_COACH_MANAGE, NOT admin
    users.push({
      userId: PHYSICIAN_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: PHYSICIAN_SESSION_ID,
      userId: PHYSICIAN_USER_ID,
      tokenHash: PHYSICIAN_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Admin — full access + admin-only endpoints
    users.push({
      userId: ADMIN_USER_ID,
      role: 'ADMIN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: ADMIN_SESSION_ID,
      userId: ADMIN_USER_ID,
      tokenHash: ADMIN_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Delegate with AI_COACH_VIEW + AI_COACH_MANAGE
    users.push({
      userId: DELEGATE_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_USER_ID,
        physicianProviderId: PHYSICIAN_PROVIDER_ID,
        permissions: ['AI_COACH_VIEW', 'AI_COACH_MANAGE'],
        linkageId: 'link-001',
      },
    });
    sessions.push({
      sessionId: DELEGATE_SESSION_ID,
      userId: DELEGATE_USER_ID,
      tokenHash: DELEGATE_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // Extension admin endpoints return 403 for physician role
  // =========================================================================

  describe('Extension admin endpoints return 403 for physician', () => {
    it('POST /intelligence/somb-change-analysis returns 403 for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /intelligence/cohorts/recalculate returns 403 for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /intelligence/rules/:id/stats returns 403 for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /intelligence/rules/:id/activate returns 403 for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Extension admin endpoints return 403 for delegate
  // =========================================================================

  describe('Extension admin endpoints return 403 for delegate', () => {
    it('POST /intelligence/somb-change-analysis returns 403 for delegate', async () => {
      const res = await injectAs(DELEGATE_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('POST /intelligence/cohorts/recalculate returns 403 for delegate', async () => {
      const res = await injectAs(DELEGATE_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
    });

    it('GET /intelligence/rules/:id/stats returns 403 for delegate', async () => {
      const res = await injectAs(DELEGATE_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).toBe(403);
    });

    it('PUT /intelligence/rules/:id/activate returns 403 for delegate', async () => {
      const res = await injectAs(DELEGATE_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Extension admin endpoints accept admin role
  // =========================================================================

  describe('Extension admin endpoints accept admin role', () => {
    it('POST /intelligence/somb-change-analysis succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/cohorts/recalculate succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/rules/:id/stats succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/rules/:id/activate succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Physician can still access physician-facing endpoints
  // =========================================================================

  describe('Physician can access physician-facing endpoints', () => {
    it('GET /intelligence/me/learning-state succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/rules succeeds for physician (list rules transparency)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/claims/:claim_id/suggestions succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/intelligence/claims/${DUMMY_UUID}/suggestions`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/me/rules/:rule_id/unsuppress succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', `/api/v1/intelligence/me/rules/${DUMMY_UUID}/unsuppress`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/me/preferences succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', '/api/v1/intelligence/me/preferences', {
        enabled_categories: ['MODIFIER_ADD'],
        disabled_categories: ['DOCUMENTATION_GAP'],
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 403 response safety — no information leakage
  // =========================================================================

  describe('403 responses do not leak sensitive information', () => {
    it('403 does not contain stack traces', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('403 does not reveal admin guard details', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Insufficient permissions');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
    });

    it('403 does not reveal which role is required', async () => {
      const res = await injectAs(DELEGATE_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('ADMIN');
      expect(rawBody).not.toContain('requireAdmin');
    });

    it('403 has consistent error shape', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });
});
