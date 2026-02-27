// ============================================================================
// Domain 7: Intelligence Extensions — Cross-Provider Learning Isolation
// Verifies that learning-state and suggestions are scoped per provider.
// Physician1 never sees physician2's learning state, and vice versa.
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
import type { IntelRepository } from '../../../src/domains/intel/intel.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities — two physicians
// ---------------------------------------------------------------------------

// Physician 1
const PHYSICIAN1_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_TOKEN_HASH = hashToken(PHYSICIAN1_TOKEN);
const PHYSICIAN1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Physician 2
const PHYSICIAN2_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_TOKEN_HASH = hashToken(PHYSICIAN2_TOKEN);
const PHYSICIAN2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const PHYSICIAN2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Test data — claims and suggestions owned by each physician
// ---------------------------------------------------------------------------

const PHYSICIAN1_CLAIM_ID = 'cccc0000-0000-0000-0000-000000000001';
const PHYSICIAN2_CLAIM_ID = 'cccc0000-0000-0000-0000-000000000002';

const PHYSICIAN1_SUGGESTION_ID = 'dddd0000-0000-0000-0000-000000000001';
const PHYSICIAN2_SUGGESTION_ID = 'dddd0000-0000-0000-0000-000000000002';

const RULE_ID = 'eeee0000-0000-0000-0000-000000000001';

function makeSuggestion(suggestionId: string, ruleId: string) {
  return {
    suggestionId,
    ruleId,
    tier: 1,
    category: 'MODIFIER_ADD',
    priority: 'MEDIUM',
    title: 'Add CMGP Modifier',
    description: 'Consider adding CMGP modifier',
    revenueImpact: 15.5,
    confidence: 0.95,
    sourceReference: 'SOMB Section 3.2',
    sourceUrl: null,
    suggestedChanges: [],
    status: 'PENDING',
    dismissedReason: null,
    createdAt: new Date().toISOString(),
    resolvedAt: null,
    resolvedBy: null,
  };
}

const P1_SUGGESTION = makeSuggestion(PHYSICIAN1_SUGGESTION_ID, RULE_ID);
const P2_SUGGESTION = makeSuggestion(PHYSICIAN2_SUGGESTION_ID, RULE_ID);

// ---------------------------------------------------------------------------
// Per-physician data stores (simulate DB scoping)
// ---------------------------------------------------------------------------

const claimSuggestions = new Map<string, any[]>();
const learningStates = new Map<string, any>();
const suggestionClaimIndex = new Map<string, { claimId: string; providerId: string }>();

function resetDataStores() {
  claimSuggestions.clear();
  learningStates.clear();
  suggestionClaimIndex.clear();

  // Seed physician 1 data
  claimSuggestions.set(`${PHYSICIAN1_CLAIM_ID}:${PHYSICIAN1_USER_ID}`, [{ ...P1_SUGGESTION }]);
  suggestionClaimIndex.set(PHYSICIAN1_SUGGESTION_ID, {
    claimId: PHYSICIAN1_CLAIM_ID,
    providerId: PHYSICIAN1_USER_ID,
  });
  learningStates.set(PHYSICIAN1_USER_ID, {
    suppressedCount: 3,
    topCategories: [{ category: 'MODIFIER_ADD', count: 15 }],
    acceptanceRate: 0.80,
    totalSuggestions: 30,
  });

  // Seed physician 2 data
  claimSuggestions.set(`${PHYSICIAN2_CLAIM_ID}:${PHYSICIAN2_USER_ID}`, [{ ...P2_SUGGESTION }]);
  suggestionClaimIndex.set(PHYSICIAN2_SUGGESTION_ID, {
    claimId: PHYSICIAN2_CLAIM_ID,
    providerId: PHYSICIAN2_USER_ID,
  });
  learningStates.set(PHYSICIAN2_USER_ID, {
    suppressedCount: 1,
    topCategories: [{ category: 'CODE_ALTERNATIVE', count: 7 }],
    acceptanceRate: 0.45,
    totalSuggestions: 12,
  });
}

// ---------------------------------------------------------------------------
// Mock stores for auth
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
// Handler deps with scoped mock data
// ---------------------------------------------------------------------------

function createScopedIntelHandlerDeps(): IntelHandlerDeps {
  const analyseDeps = {
    contextDeps: {
      getClaim: vi.fn(async (claimId: string, providerId: string) => {
        const key = `${claimId}:${providerId}`;
        if (claimSuggestions.has(key)) {
          return { claimId, providerId, claimType: 'AHCIP', healthServiceCode: '03.04A', dateOfService: '2026-01-15' };
        }
        return null;
      }),
      getAhcipDetails: vi.fn(async () => null),
      getWcbDetails: vi.fn(async () => null),
      getPatientDemographics: vi.fn(async () => ({ age: 45, gender: 'M' })),
      getProvider: vi.fn(async () => ({ specialtyCode: 'GP', physicianType: 'GENERAL', defaultLocation: null })),
      getDefaultLocation: vi.fn(async () => null),
      getHscCode: vi.fn(async () => null),
      getModifierDefinitions: vi.fn(async () => []),
      getDiCode: vi.fn(async () => null),
      getReferenceSet: vi.fn(async () => []),
      getCrossClaimCount: vi.fn(async () => 0),
      getCrossClaimSum: vi.fn(async () => '0.00'),
      getCrossClaimExists: vi.fn(async () => false),
    },
    tier1Deps: {
      getActiveRulesForClaim: vi.fn(async () => []),
      getProviderLearningForRules: vi.fn(async () => []),
      incrementShown: vi.fn(async () => {}),
      appendSuggestionEvent: vi.fn(async () => {}),
    },
    tier2Deps: {
      buildPrompt: vi.fn(),
      callLlm: vi.fn(),
      parseResponse: vi.fn(),
      appendSuggestionEvent: vi.fn(async () => {}),
    },
    lifecycleDeps: {
      getClaimSuggestions: vi.fn(async (claimId: string, providerId: string) => {
        const key = `${claimId}:${providerId}`;
        return claimSuggestions.get(key) ?? null;
      }),
      updateClaimSuggestions: vi.fn(async (claimId: string, providerId: string, suggestions: any[]) => {
        const key = `${claimId}:${providerId}`;
        claimSuggestions.set(key, suggestions);
      }),
      applyClaimChanges: vi.fn(async () => {}),
      revalidateClaim: vi.fn(async () => {}),
      appendSuggestionEvent: vi.fn(async () => {}),
      recordAcceptance: vi.fn(async () => {}),
      recordDismissal: vi.fn(async () => {}),
    },
    auditLog: vi.fn(async () => {}),
    notifyWs: vi.fn(),
  } as any;

  const lifecycleDeps = {
    getClaimSuggestions: vi.fn(async (claimId: string, providerId: string) => {
      const key = `${claimId}:${providerId}`;
      return claimSuggestions.get(key) ?? null;
    }),
    updateClaimSuggestions: vi.fn(async (claimId: string, providerId: string, suggestions: any[]) => {
      const key = `${claimId}:${providerId}`;
      claimSuggestions.set(key, suggestions);
    }),
    applyClaimChanges: vi.fn(async () => {}),
    revalidateClaim: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => {}),
    recordDismissal: vi.fn(async () => {}),
  };

  const learningLoopDeps = {
    getProviderLearning: vi.fn(async (providerId: string) => {
      return learningStates.get(providerId) ?? null;
    }),
    unsuppressRule: vi.fn(async (providerId: string, ruleId: string) => {
      const state = learningStates.get(providerId);
      if (!state) return null;
      if (state.suppressedCount > 0) {
        state.suppressedCount -= 1;
        return { providerId, ruleId, isSuppressed: false };
      }
      return null;
    }),
    processRejection: vi.fn(async () => {}),
    recalculateAllCohorts: vi.fn(async () => []),
    deleteSmallCohorts: vi.fn(async () => 0),
  };

  const sombChangeDeps = {
    getRulesByVersion: vi.fn(async () => []),
    getAffectedProviders: vi.fn(async () => []),
    generateImpactReport: vi.fn(async () => ({
      totalAffectedPhysicians: 0,
      totalAffectedRules: 0,
      impacts: [],
    })),
  };

  const stubRepo: IntelRepository = {
    listRules: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    getRule: vi.fn(async () => null),
    createRule: vi.fn(async () => null),
    updateRule: vi.fn(async () => null),
    activateRule: vi.fn(async () => null),
    getRuleStats: vi.fn(async () => null),
    getLearningStateSummary: vi.fn(async (providerId: string) => {
      return learningStates.get(providerId) ?? {
        suppressedCount: 0,
        topCategories: [],
        acceptanceRate: 0,
        totalSuggestions: 0,
      };
    }),
    findClaimIdBySuggestionId: vi.fn(async (suggestionId: string) => {
      const entry = suggestionClaimIndex.get(suggestionId);
      return entry?.claimId ?? null;
    }),
    getActiveRulesForClaim: vi.fn(async () => []),
    getProviderLearningForRules: vi.fn(async () => []),
    incrementShown: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => {}),
    getClaimSuggestions: vi.fn(async (claimId: string, providerId: string) => {
      const key = `${claimId}:${providerId}`;
      return claimSuggestions.get(key) ?? null;
    }),
    updateClaimSuggestions: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => {}),
    recordDismissal: vi.fn(async () => {}),
    unsuppressRule: vi.fn(async (providerId: string, ruleId: string) => {
      const state = learningStates.get(providerId);
      if (!state) return null;
      if (state.suppressedCount > 0) {
        state.suppressedCount -= 1;
        return { providerId, ruleId, isSuppressed: false };
      }
      return null;
    }),
    listCohorts: vi.fn(async () => []),
    upsertCohort: vi.fn(async () => null),
    deleteSmallCohorts: vi.fn(async () => 0),
    getProvidersBySpecialty: vi.fn(async () => []),
    getProviderLearningByRule: vi.fn(async () => []),
    listSuggestionEvents: vi.fn(async () => []),
  } as unknown as IntelRepository;

  return {
    analyseDeps,
    lifecycleDeps,
    learningLoopDeps,
    sombChangeDeps,
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

  await testApp.register(intelRoutes, { deps: createScopedIntelHandlerDeps() });
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

function makeSession(id: string, userId: string, tokenHash: string): MockSession {
  return {
    sessionId: id,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Extensions Cross-Provider Learning Isolation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];
    resetDataStores();

    // Physician 1
    users.push({
      userId: PHYSICIAN1_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push(makeSession(PHYSICIAN1_SESSION_ID, PHYSICIAN1_USER_ID, PHYSICIAN1_TOKEN_HASH));

    // Physician 2
    users.push({
      userId: PHYSICIAN2_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push(makeSession(PHYSICIAN2_SESSION_ID, PHYSICIAN2_USER_ID, PHYSICIAN2_TOKEN_HASH));
  });

  // =========================================================================
  // Learning State Isolation
  // =========================================================================

  describe('Learning state isolation across providers', () => {
    it('physician1 sees only their own learning state', async () => {
      const res = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(3);
      expect(body.data.acceptanceRate).toBe(0.80);
      expect(body.data.totalSuggestions).toBe(30);
    });

    it('physician2 sees only their own learning state', async () => {
      const res = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(1);
      expect(body.data.acceptanceRate).toBe(0.45);
      expect(body.data.totalSuggestions).toBe(12);
    });

    it('physician1 and physician2 learning states are fully distinct', async () => {
      const res1 = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const res2 = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      const state1 = JSON.parse(res1.body).data;
      const state2 = JSON.parse(res2.body).data;

      expect(state1.suppressedCount).not.toBe(state2.suppressedCount);
      expect(state1.acceptanceRate).not.toBe(state2.acceptanceRate);
      expect(state1.totalSuggestions).not.toBe(state2.totalSuggestions);
    });
  });

  // =========================================================================
  // Suggestion Scoping
  // =========================================================================

  describe('Suggestion scoping to provider', () => {
    it('physician1 can view their own claim suggestions', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].suggestionId).toBe(PHYSICIAN1_SUGGESTION_ID);
    });

    it('physician2 cannot view physician1 suggestions -- returns empty', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
    });

    it('physician1 cannot view physician2 suggestions -- returns empty', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
    });

    it('physician2 can view their own claim suggestions', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].suggestionId).toBe(PHYSICIAN2_SUGGESTION_ID);
    });
  });

  // =========================================================================
  // Unsuppress Isolation
  // =========================================================================

  describe('Unsuppress rule isolation', () => {
    it('physician1 unsuppressing a rule does not affect physician2', async () => {
      await injectAs(PHYSICIAN1_TOKEN, 'POST', `/api/v1/intelligence/me/rules/${RULE_ID}/unsuppress`);

      const res2 = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const state2 = JSON.parse(res2.body).data;
      expect(state2.suppressedCount).toBe(1);
    });

    it('physician1 unsuppress only modifies physician1 state', async () => {
      const beforeRes = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const beforeCount = JSON.parse(beforeRes.body).data.suppressedCount;
      expect(beforeCount).toBe(3);

      await injectAs(PHYSICIAN1_TOKEN, 'POST', `/api/v1/intelligence/me/rules/${RULE_ID}/unsuppress`);

      const afterRes = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const afterCount = JSON.parse(afterRes.body).data.suppressedCount;
      expect(afterCount).toBe(2);
    });
  });

  // =========================================================================
  // Cross-provider suggestion actions return 404
  // =========================================================================

  describe('Cross-provider suggestion actions return 404', () => {
    it('physician2 cannot accept physician1 suggestion -- returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('physician1 cannot dismiss physician2 suggestion -- returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN2_SUGGESTION_ID}/dismiss`,
        { reason: 'not_applicable' },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('cross-provider 404 does not leak resource existence', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_SUGGESTION_ID);
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_CLAIM_ID);
    });
  });
});
