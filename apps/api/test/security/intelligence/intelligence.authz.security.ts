// ============================================================================
// Domain 7: Intelligence Engine — Authorization & Permission Enforcement
// Verifies role-based access, delegate permission boundaries, admin-only
// endpoints, and physician transparency (sanitised rule data).
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

// Physician user — has all permissions (role = PHYSICIAN)
const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Admin user — has all permissions + admin-only access
const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// Delegate with AI_COACH_VIEW only — can view, cannot manage
const DELEGATE_VIEW_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_TOKEN_HASH = hashToken(DELEGATE_VIEW_TOKEN);
const DELEGATE_VIEW_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE_VIEW_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';

// Delegate with AI_COACH_VIEW + AI_COACH_MANAGE — can view and manage
const DELEGATE_MANAGE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_MANAGE_TOKEN_HASH = hashToken(DELEGATE_MANAGE_TOKEN);
const DELEGATE_MANAGE_USER_ID = 'aaaa0000-0000-0000-0000-000000000004';
const DELEGATE_MANAGE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000004';

// Delegate with NO AI_COACH permissions at all
const DELEGATE_NONE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_TOKEN_HASH = hashToken(DELEGATE_NONE_TOKEN);
const DELEGATE_NONE_USER_ID = 'aaaa0000-0000-0000-0000-000000000005';
const DELEGATE_NONE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000005';

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

  // listRules returns mock data so we can verify admin vs physician transparency
  const mockRules = [
    {
      ruleId: DUMMY_UUID,
      name: 'Test CMGP Modifier Rule',
      category: 'MODIFIER_ADD',
      claimType: 'AHCIP',
      conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
      suggestionTemplate: {
        title: 'Add CMGP Modifier',
        description: 'Consider adding CMGP modifier for comprehensive care',
        source_reference: 'SOMB Section 3.2',
      },
      priorityFormula: 'fixed:MEDIUM',
      specialtyFilter: null,
      sombVersion: '2026-01',
      isActive: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ];

  const stubRepo: IntelRepository = {
    listRules: vi.fn(async () => ({
      data: mockRules,
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
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
let handlerDeps: IntelHandlerDeps;

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

  handlerDeps = createStubIntelHandlerDeps();
  await testApp.register(intelRoutes, { deps: handlerDeps });
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
// Valid payloads for routes that require request bodies
// ---------------------------------------------------------------------------

const VALID_ANALYSE_PAYLOAD = {
  claim_id: DUMMY_UUID,
  claim_context: {
    claim_type: 'AHCIP',
    health_service_code: '03.04A',
    modifiers: [],
    date_of_service: '2026-01-15',
    provider_specialty: 'GP',
    patient_demographics_anonymised: { age_range: '40-50', gender: 'M' },
    diagnostic_codes: [],
  },
};

const VALID_DISMISS_PAYLOAD = { reason: 'not_applicable' };

const VALID_PREFERENCES_PAYLOAD = {
  enabled_categories: ['MODIFIER_ADD'],
  disabled_categories: ['DOCUMENTATION_GAP'],
};

const VALID_CREATE_RULE_PAYLOAD = {
  name: 'Test rule',
  category: 'MODIFIER_ADD',
  claim_type: 'AHCIP',
  conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
  suggestion_template: {
    title: 'Test',
    description: 'Test description',
    source_reference: 'SOMB',
  },
  priority_formula: 'fixed:MEDIUM',
};

const VALID_UPDATE_RULE_PAYLOAD = { name: 'Updated rule' };

const VALID_ACTIVATE_RULE_PAYLOAD = { is_active: true };

const VALID_SOMB_CHANGE_PAYLOAD = { old_version: '2025-12', new_version: '2026-01' };

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Engine Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    // Physician — full access to AI_COACH_VIEW and AI_COACH_MANAGE
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

    // Delegate with AI_COACH_VIEW only
    users.push({
      userId: DELEGATE_VIEW_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_VIEW_USER_ID,
        physicianProviderId: PHYSICIAN_PROVIDER_ID,
        permissions: ['AI_COACH_VIEW'],
        linkageId: 'link-001',
      },
    });
    sessions.push({
      sessionId: DELEGATE_VIEW_SESSION_ID,
      userId: DELEGATE_VIEW_USER_ID,
      tokenHash: DELEGATE_VIEW_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Delegate with AI_COACH_VIEW + AI_COACH_MANAGE
    users.push({
      userId: DELEGATE_MANAGE_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_MANAGE_USER_ID,
        physicianProviderId: PHYSICIAN_PROVIDER_ID,
        permissions: ['AI_COACH_VIEW', 'AI_COACH_MANAGE'],
        linkageId: 'link-002',
      },
    });
    sessions.push({
      sessionId: DELEGATE_MANAGE_SESSION_ID,
      userId: DELEGATE_MANAGE_USER_ID,
      tokenHash: DELEGATE_MANAGE_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Delegate with NO AI_COACH permissions
    users.push({
      userId: DELEGATE_NONE_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_NONE_USER_ID,
        physicianProviderId: PHYSICIAN_PROVIDER_ID,
        permissions: ['CLAIM_VIEW'],
        linkageId: 'link-003',
      },
    });
    sessions.push({
      sessionId: DELEGATE_NONE_SESSION_ID,
      userId: DELEGATE_NONE_USER_ID,
      tokenHash: DELEGATE_NONE_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // Permission enforcement: AI_COACH_VIEW required
  // =========================================================================

  describe('AI_COACH_VIEW permission enforcement', () => {
    it('POST /intelligence/analyse returns 403 for delegate without AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'POST', '/api/v1/intelligence/analyse', VALID_ANALYSE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /intelligence/claims/:claim_id/suggestions returns 403 for delegate without AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', `/api/v1/intelligence/claims/${DUMMY_UUID}/suggestions`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('GET /intelligence/me/learning-state returns 403 for delegate without AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('GET /intelligence/rules returns 403 for delegate without AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_NONE_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // Permission enforcement: AI_COACH_MANAGE required
  // =========================================================================

  describe('AI_COACH_MANAGE permission enforcement', () => {
    it('POST /intelligence/suggestions/:id/accept returns 403 for delegate without AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/accept`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /intelligence/suggestions/:id/dismiss returns 403 for delegate without AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`, VALID_DISMISS_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /intelligence/me/rules/:rule_id/unsuppress returns 403 for delegate without AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', `/api/v1/intelligence/me/rules/${DUMMY_UUID}/unsuppress`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('PUT /intelligence/me/preferences returns 403 for delegate without AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'PUT', '/api/v1/intelligence/me/preferences', VALID_PREFERENCES_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // Admin-only endpoint enforcement
  // =========================================================================

  describe('Admin-only endpoint enforcement', () => {
    it('POST /intelligence/rules returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/rules', VALID_CREATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /intelligence/rules/:id returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}`, VALID_UPDATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('PUT /intelligence/rules/:id/activate returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('GET /intelligence/rules/:id/stats returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /intelligence/cohorts/recalculate returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('POST /intelligence/somb-change-analysis returns 403 for physician (non-admin)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    // Also verify delegates cannot access admin-only endpoints
    it('POST /intelligence/rules returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', '/api/v1/intelligence/rules', VALID_CREATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('PUT /intelligence/rules/:id returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}`, VALID_UPDATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('PUT /intelligence/rules/:id/activate returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });

    it('GET /intelligence/rules/:id/stats returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).toBe(403);
    });

    it('POST /intelligence/cohorts/recalculate returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
    });

    it('POST /intelligence/somb-change-analysis returns 403 for delegate (non-admin)', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Admin-only endpoints: admin CAN access (positive case)
  // =========================================================================

  describe('Admin-only endpoints accept admin role', () => {
    it('POST /intelligence/rules succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/rules', VALID_CREATE_RULE_PAYLOAD);
      // Should not be 403 — may be 201, 200, or 500 depending on stub, but never 403/401
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/rules/:id succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}`, VALID_UPDATE_RULE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/rules/:id/activate succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, VALID_ACTIVATE_RULE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/rules/:id/stats succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/cohorts/recalculate succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/somb-change-analysis succeeds for admin', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', VALID_SOMB_CHANGE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Physician transparency: sanitised rule data for non-admins
  // =========================================================================

  describe('Physician transparency — sanitised rule data', () => {
    it('GET /intelligence/rules as physician returns name + category only, no conditions JSONB', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);

      for (const rule of body.data) {
        // Should have name and category
        expect(rule.name).toBeDefined();
        expect(rule.category).toBeDefined();
        // Should NOT have conditions, priorityFormula, or full suggestionTemplate
        expect(rule.conditions).toBeUndefined();
        expect(rule.priorityFormula).toBeUndefined();
        expect(rule.suggestionTemplate).toBeUndefined();
        expect(rule.sombVersion).toBeUndefined();
        expect(rule.specialtyFilter).toBeUndefined();
      }
    });

    it('GET /intelligence/rules as admin returns full rule including conditions', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);

      for (const rule of body.data) {
        // Admin sees full rule data including conditions
        expect(rule.name).toBeDefined();
        expect(rule.category).toBeDefined();
        expect(rule.conditions).toBeDefined();
        expect(rule.suggestionTemplate).toBeDefined();
        expect(rule.priorityFormula).toBeDefined();
      }
    });

    it('GET /intelligence/rules as delegate with AI_COACH_VIEW returns sanitised data', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.length).toBeGreaterThan(0);

      for (const rule of body.data) {
        expect(rule.name).toBeDefined();
        expect(rule.category).toBeDefined();
        expect(rule.conditions).toBeUndefined();
        expect(rule.priorityFormula).toBeUndefined();
        expect(rule.suggestionTemplate).toBeUndefined();
      }
    });
  });

  // =========================================================================
  // Delegate positive cases: permitted actions succeed
  // =========================================================================

  describe('Delegate with AI_COACH_VIEW can access view endpoints', () => {
    it('GET /intelligence/claims/:claim_id/suggestions succeeds for delegate with AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', `/api/v1/intelligence/claims/${DUMMY_UUID}/suggestions`);
      // Not 401 or 403 — the request passes auth and permission checks
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/me/learning-state succeeds for delegate with AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/analyse succeeds for delegate with AI_COACH_VIEW', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/intelligence/analyse', VALID_ANALYSE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  describe('Delegate with AI_COACH_MANAGE can access manage endpoints', () => {
    it('POST /intelligence/suggestions/:id/accept succeeds for delegate with AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/accept`);
      // Not 403 — auth passes
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/suggestions/:id/dismiss succeeds for delegate with AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`, VALID_DISMISS_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/me/preferences succeeds for delegate with AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'PUT', '/api/v1/intelligence/me/preferences', VALID_PREFERENCES_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/me/rules/:rule_id/unsuppress succeeds for delegate with AI_COACH_MANAGE', async () => {
      const res = await injectAs(DELEGATE_MANAGE_TOKEN, 'POST', `/api/v1/intelligence/me/rules/${DUMMY_UUID}/unsuppress`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 403 response safety — no information leakage
  // =========================================================================

  describe('403 responses do not leak sensitive information', () => {
    it('403 does not contain stack traces', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/rules', VALID_CREATE_RULE_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('403 does not reveal which permission was missing', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/accept`);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('AI_COACH_MANAGE');
      expect(rawBody).not.toContain('AI_COACH_VIEW');
    });

    it('403 does not reveal endpoint internals (admin guard details)', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Insufficient permissions');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
    });

    it('403 has consistent error shape', async () => {
      const res = await injectAs(DELEGATE_VIEW_TOKEN, 'PUT', '/api/v1/intelligence/me/preferences', VALID_PREFERENCES_PAYLOAD);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // Physician positive cases: physicians have all permissions
  // =========================================================================

  describe('Physician has full access to non-admin endpoints', () => {
    it('POST /intelligence/analyse succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', '/api/v1/intelligence/analyse', VALID_ANALYSE_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/claims/:claim_id/suggestions succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', `/api/v1/intelligence/claims/${DUMMY_UUID}/suggestions`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/suggestions/:id/accept succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/accept`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /intelligence/suggestions/:id/dismiss succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'POST', `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`, VALID_DISMISS_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/me/learning-state succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /intelligence/me/preferences succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'PUT', '/api/v1/intelligence/me/preferences', VALID_PREFERENCES_PAYLOAD);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /intelligence/rules succeeds for physician', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });
});
