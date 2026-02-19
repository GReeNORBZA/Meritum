// ============================================================================
// Domain 7: Intelligence Engine — Physician Tenant Isolation (Security)
// Verifies cross-physician data isolation: physician1 never sees physician2's
// suggestions, learning state, or claim analysis results.
// All cross-physician access returns 404, not 403.
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
// Fixed test identities — two physicians + two delegates
// ---------------------------------------------------------------------------

// Physician 1
const PHYSICIAN1_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_TOKEN_HASH = hashToken(PHYSICIAN1_TOKEN);
const PHYSICIAN1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';
const PHYSICIAN1_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000001';

// Physician 2
const PHYSICIAN2_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_TOKEN_HASH = hashToken(PHYSICIAN2_TOKEN);
const PHYSICIAN2_USER_ID = 'aaaa0000-0000-0000-0000-000000000002';
const PHYSICIAN2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000002';
const PHYSICIAN2_PROVIDER_ID = 'pppp0000-0000-0000-0000-000000000002';

// Delegate for Physician 1 (has AI_COACH_VIEW + AI_COACH_MANAGE)
const DELEGATE_P1_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_P1_TOKEN_HASH = hashToken(DELEGATE_P1_TOKEN);
const DELEGATE_P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000003';
const DELEGATE_P1_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000003';

// Same delegate switches to Physician 2 context
const DELEGATE_P2_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_P2_TOKEN_HASH = hashToken(DELEGATE_P2_TOKEN);
const DELEGATE_P2_USER_ID = 'aaaa0000-0000-0000-0000-000000000004';
const DELEGATE_P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000004';

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

// Physician 1 owns suggestion on claim 1
const P1_SUGGESTION = makeSuggestion(PHYSICIAN1_SUGGESTION_ID, RULE_ID);
// Physician 2 owns suggestion on claim 2
const P2_SUGGESTION = makeSuggestion(PHYSICIAN2_SUGGESTION_ID, RULE_ID);

// ---------------------------------------------------------------------------
// Per-physician data stores (simulate DB scoping)
// ---------------------------------------------------------------------------

/** Claims JSONB keyed by `${claimId}:${providerId}` for scoped access */
const claimSuggestions = new Map<string, any[]>();

/** Learning state keyed by providerId */
const learningStates = new Map<string, any>();

/** Suggestion event index: suggestionId -> { claimId, providerId } */
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
    suppressedCount: 2,
    topCategories: [{ category: 'MODIFIER_ADD', count: 10 }],
    acceptanceRate: 0.75,
    totalSuggestions: 20,
  });

  // Seed physician 2 data
  claimSuggestions.set(`${PHYSICIAN2_CLAIM_ID}:${PHYSICIAN2_USER_ID}`, [{ ...P2_SUGGESTION }]);
  suggestionClaimIndex.set(PHYSICIAN2_SUGGESTION_ID, {
    claimId: PHYSICIAN2_CLAIM_ID,
    providerId: PHYSICIAN2_USER_ID,
  });
  learningStates.set(PHYSICIAN2_USER_ID, {
    suppressedCount: 0,
    topCategories: [{ category: 'CODE_ALTERNATIVE', count: 5 }],
    acceptanceRate: 0.50,
    totalSuggestions: 10,
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
  // AnalyseDeps — analyseClaim checks claim ownership via contextDeps.getClaim
  const analyseDeps = {
    contextDeps: {
      getClaim: vi.fn(async (claimId: string, providerId: string) => {
        // Only return claim if the provider owns it
        const key = `${claimId}:${providerId}`;
        if (claimSuggestions.has(key)) {
          return {
            claimId,
            providerId,
            claimType: 'AHCIP',
            healthServiceCode: '03.04A',
            dateOfService: '2026-01-15',
          };
        }
        return null; // Not found — wrong physician
      }),
      getAhcipDetails: vi.fn(async () => null),
      getWcbDetails: vi.fn(async () => null),
      getPatientDemographics: vi.fn(async () => ({ age: 45, gender: 'M' })),
      getProvider: vi.fn(async () => ({
        specialtyCode: 'GP',
        physicianType: 'GENERAL',
        defaultLocation: null,
      })),
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

  // LifecycleDeps — getClaimSuggestions/accept/dismiss scoped by providerId
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

  // LearningLoopDeps — scoped by providerId
  const learningLoopDeps = {
    getProviderLearning: vi.fn(async (providerId: string) => {
      return learningStates.get(providerId) ?? null;
    }),
    unsuppressRule: vi.fn(async (providerId: string, ruleId: string) => {
      const state = learningStates.get(providerId);
      if (!state) return null;
      // Only unsuppress if the provider has a suppressed count > 0
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
// Valid payloads
// ---------------------------------------------------------------------------

const VALID_ANALYSE_PAYLOAD = {
  claim_id: PHYSICIAN1_CLAIM_ID,
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

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Engine Physician Tenant Isolation (Security)', () => {
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

    // Delegate acting under Physician 1 context
    users.push({
      userId: DELEGATE_P1_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_P1_USER_ID,
        physicianProviderId: PHYSICIAN1_PROVIDER_ID,
        permissions: ['AI_COACH_VIEW', 'AI_COACH_MANAGE'],
        linkageId: 'link-001',
      },
    });
    sessions.push(makeSession(DELEGATE_P1_SESSION_ID, DELEGATE_P1_USER_ID, DELEGATE_P1_TOKEN_HASH));

    // Delegate acting under Physician 2 context
    users.push({
      userId: DELEGATE_P2_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      delegateContext: {
        delegateUserId: DELEGATE_P2_USER_ID,
        physicianProviderId: PHYSICIAN2_PROVIDER_ID,
        permissions: ['AI_COACH_VIEW', 'AI_COACH_MANAGE'],
        linkageId: 'link-002',
      },
    });
    sessions.push(makeSession(DELEGATE_P2_SESSION_ID, DELEGATE_P2_USER_ID, DELEGATE_P2_TOKEN_HASH));
  });

  // =========================================================================
  // Suggestion Isolation
  // =========================================================================

  describe('Suggestion isolation', () => {
    it('physician2 cannot view physician1\'s claim suggestions — returns 404/empty', async () => {
      // Physician1 has suggestions on PHYSICIAN1_CLAIM_ID
      // Physician2 requests them — should get empty array (scoped query returns nothing)
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Scoped query returns empty — physician2 has no suggestions on this claim
      expect(body.data).toEqual([]);
    });

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

    it('physician2 cannot accept physician1\'s suggestion — returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      // Must not leak details about the suggestion
      expect(body.data).toBeUndefined();
    });

    it('physician2 cannot dismiss physician1\'s suggestion — returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/dismiss`,
        VALID_DISMISS_PAYLOAD,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.data).toBeUndefined();
    });

    it('physician1 cannot accept physician2\'s suggestion — returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN2_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('physician1 cannot dismiss physician2\'s suggestion — returns 404', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN2_SUGGESTION_ID}/dismiss`,
        VALID_DISMISS_PAYLOAD,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('suggestion acceptance by physician2 does not modify physician1\'s suggestion state', async () => {
      // Physician2 attempts to accept physician1's suggestion (should 404)
      await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      // Verify physician1's suggestion is still PENDING (untouched)
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      const body = JSON.parse(res.body);
      const suggestion = body.data.find((s: any) => s.suggestionId === PHYSICIAN1_SUGGESTION_ID);
      expect(suggestion).toBeDefined();
      expect(suggestion.status).toBe('PENDING');
    });
  });

  // =========================================================================
  // Learning State Isolation
  // =========================================================================

  describe('Learning state isolation', () => {
    it('physician1 sees only their own learning state', async () => {
      const res = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(2);
      expect(body.data.acceptanceRate).toBe(0.75);
      expect(body.data.totalSuggestions).toBe(20);
    });

    it('physician2 sees only their own learning state', async () => {
      const res = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(0);
      expect(body.data.acceptanceRate).toBe(0.50);
      expect(body.data.totalSuggestions).toBe(10);
    });

    it('physician2 cannot access physician1\'s learning state — data is distinct', async () => {
      const res1 = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const res2 = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      const state1 = JSON.parse(res1.body).data;
      const state2 = JSON.parse(res2.body).data;

      // States must be different (confirming scoped data, not shared)
      expect(state1.suppressedCount).not.toBe(state2.suppressedCount);
      expect(state1.acceptanceRate).not.toBe(state2.acceptanceRate);
      expect(state1.totalSuggestions).not.toBe(state2.totalSuggestions);
    });
  });

  // =========================================================================
  // Unsuppress Rule Isolation
  // =========================================================================

  describe('Unsuppress rule isolation', () => {
    it('physician1 unsuppressing a rule does not affect physician2\'s suppression state', async () => {
      // Physician1 has suppressedCount=2, physician2 has suppressedCount=0
      // Physician1 unsuppresses a rule
      await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        `/api/v1/intelligence/me/rules/${RULE_ID}/unsuppress`,
      );

      // Physician2's state should be unchanged
      const res2 = await injectAs(PHYSICIAN2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const state2 = JSON.parse(res2.body).data;
      expect(state2.suppressedCount).toBe(0);
    });

    it('physician1 unsuppressing a rule only modifies physician1\'s state', async () => {
      const beforeRes = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const beforeCount = JSON.parse(beforeRes.body).data.suppressedCount;
      expect(beforeCount).toBe(2);

      // Unsuppress
      await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        `/api/v1/intelligence/me/rules/${RULE_ID}/unsuppress`,
      );

      const afterRes = await injectAs(PHYSICIAN1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');
      const afterCount = JSON.parse(afterRes.body).data.suppressedCount;
      expect(afterCount).toBe(1); // Decreased by 1
    });
  });

  // =========================================================================
  // Claim Analysis Isolation
  // =========================================================================

  describe('Claim analysis isolation', () => {
    it('physician2 cannot trigger analysis on physician1\'s claim — returns empty results', async () => {
      // Physician2 submits physician1's claim_id for analysis
      const res = await injectAs(PHYSICIAN2_TOKEN, 'POST', '/api/v1/intelligence/analyse', {
        ...VALID_ANALYSE_PAYLOAD,
        claim_id: PHYSICIAN1_CLAIM_ID,
      });

      // The handler calls analyseClaim with physician2's ID.
      // contextDeps.getClaim will return null (wrong physician), so no rules fire.
      // Should return 200 with empty suggestions (claim not found for this physician).
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
    });

    it('physician1 can trigger analysis on their own claim', async () => {
      const res = await injectAs(PHYSICIAN1_TOKEN, 'POST', '/api/v1/intelligence/analyse', VALID_ANALYSE_PAYLOAD);

      // Should succeed without auth/permission error
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(404);
    });

    it('physician2 cannot trigger analysis on physician1\'s claim using physician2\'s claim_id', async () => {
      // Physician1 tries to analyse physician2's claim
      const res = await injectAs(PHYSICIAN1_TOKEN, 'POST', '/api/v1/intelligence/analyse', {
        ...VALID_ANALYSE_PAYLOAD,
        claim_id: PHYSICIAN2_CLAIM_ID,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // No suggestions returned because claim doesn't belong to physician1
      expect(body.data).toEqual([]);
    });
  });

  // =========================================================================
  // Delegate Context Isolation
  // =========================================================================

  describe('Delegate isolation', () => {
    it('delegate in physician1 context sees physician1\'s suggestions only', async () => {
      // Delegate for physician1 context — should use physician1's provider ID
      // But the handler uses getPhysicianId which for delegates returns
      // delegateContext.physicianProviderId. Our data is keyed by userId,
      // and the delegate context points to PHYSICIAN1_PROVIDER_ID.
      // We need to seed data keyed by the provider ID that delegates resolve to.
      claimSuggestions.set(`${PHYSICIAN1_CLAIM_ID}:${PHYSICIAN1_PROVIDER_ID}`, [{ ...P1_SUGGESTION }]);

      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].suggestionId).toBe(PHYSICIAN1_SUGGESTION_ID);
    });

    it('delegate in physician1 context cannot see physician2\'s suggestions', async () => {
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Empty — scoped to physician1's provider ID, physician2's data not accessible
      expect(body.data).toEqual([]);
    });

    it('delegate in physician2 context sees physician2\'s suggestions only', async () => {
      // Seed data keyed by physician2's provider ID
      claimSuggestions.set(`${PHYSICIAN2_CLAIM_ID}:${PHYSICIAN2_PROVIDER_ID}`, [{ ...P2_SUGGESTION }]);

      const res = await injectAs(
        DELEGATE_P2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].suggestionId).toBe(PHYSICIAN2_SUGGESTION_ID);
    });

    it('delegate in physician2 context cannot see physician1\'s suggestions', async () => {
      const res = await injectAs(
        DELEGATE_P2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
    });

    it('delegate in physician1 context sees physician1\'s learning state', async () => {
      // Seed learning state keyed by physician1's provider ID
      learningStates.set(PHYSICIAN1_PROVIDER_ID, {
        suppressedCount: 2,
        topCategories: [{ category: 'MODIFIER_ADD', count: 10 }],
        acceptanceRate: 0.75,
        totalSuggestions: 20,
      });

      const res = await injectAs(DELEGATE_P1_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(2);
      expect(body.data.acceptanceRate).toBe(0.75);
    });

    it('delegate in physician2 context sees physician2\'s learning state', async () => {
      // Seed learning state keyed by physician2's provider ID
      learningStates.set(PHYSICIAN2_PROVIDER_ID, {
        suppressedCount: 0,
        topCategories: [{ category: 'CODE_ALTERNATIVE', count: 5 }],
        acceptanceRate: 0.50,
        totalSuggestions: 10,
      });

      const res = await injectAs(DELEGATE_P2_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.suppressedCount).toBe(0);
      expect(body.data.acceptanceRate).toBe(0.50);
    });

    it('delegate cannot accept suggestions across physician contexts', async () => {
      // Delegate in physician1 context tries to accept physician2's suggestion
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN2_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('delegate cannot dismiss suggestions across physician contexts', async () => {
      // Delegate in physician1 context tries to dismiss physician2's suggestion
      const res = await injectAs(
        DELEGATE_P1_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN2_SUGGESTION_ID}/dismiss`,
        VALID_DISMISS_PAYLOAD,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // Cross-physician access always returns 404, never 403
  // =========================================================================

  describe('Cross-physician access returns 404 (never 403)', () => {
    it('accessing another physician\'s claim suggestions returns 200 with empty data, not 403', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      // 200 with empty data (claim doesn't exist for this physician)
      // NOT 403 which would confirm the claim exists
      expect(res.statusCode).toBe(200);
      expect(res.statusCode).not.toBe(403);
    });

    it('accepting another physician\'s suggestion returns 404, not 403', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('dismissing another physician\'s suggestion returns 404, not 403', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/dismiss`,
        VALID_DISMISS_PAYLOAD,
      );

      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('cross-physician 404 responses do not leak resource existence', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      // Generic message — does not mention "suggestion" or the ID
      expect(body.error.message).toBe('Resource not found');
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_SUGGESTION_ID);
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_CLAIM_ID);
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_USER_ID);
    });
  });
});
