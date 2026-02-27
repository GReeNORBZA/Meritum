// ============================================================================
// Domain 7: Intelligence Extensions — Data Leakage Prevention (Security)
// Verifies suggestion data does not leak cross-provider, no tech headers
// are exposed, and extension endpoint responses are sanitised.
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
// Fixed test identities
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

// Admin
const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000099';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000099';

// Test data
const PHYSICIAN1_CLAIM_ID = 'cccc0000-0000-0000-0000-000000000001';
const PHYSICIAN2_CLAIM_ID = 'cccc0000-0000-0000-0000-000000000002';
const PHYSICIAN1_SUGGESTION_ID = 'dddd0000-0000-0000-0000-000000000001';
const PHYSICIAN2_SUGGESTION_ID = 'dddd0000-0000-0000-0000-000000000002';
const RULE_ID = 'eeee0000-0000-0000-0000-000000000001';
const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

function makeSuggestion(suggestionId: string, ruleId: string, providerSpecificData: string) {
  return {
    suggestionId,
    ruleId,
    tier: 1,
    category: 'MODIFIER_ADD',
    priority: 'MEDIUM',
    title: 'Add CMGP Modifier',
    description: `Consider adding CMGP modifier - ${providerSpecificData}`,
    revenueImpact: 15.5,
    confidence: 0.95,
    sourceReference: 'SOMB Section 3.2',
    sourceUrl: null,
    suggestedChanges: [{ field: 'modifier1', value_formula: 'CMGP' }],
    status: 'PENDING',
    dismissedReason: null,
    createdAt: new Date().toISOString(),
    resolvedAt: null,
    resolvedBy: null,
  };
}

// ---------------------------------------------------------------------------
// Per-physician data stores
// ---------------------------------------------------------------------------

const claimSuggestions = new Map<string, any[]>();
const suggestionClaimIndex = new Map<string, { claimId: string; providerId: string }>();

let forceInternalError = false;

function resetDataStores() {
  claimSuggestions.clear();
  suggestionClaimIndex.clear();
  forceInternalError = false;

  // Physician 1 suggestions
  claimSuggestions.set(`${PHYSICIAN1_CLAIM_ID}:${PHYSICIAN1_USER_ID}`, [
    makeSuggestion(PHYSICIAN1_SUGGESTION_ID, RULE_ID, 'provider1-secret-detail'),
  ]);
  suggestionClaimIndex.set(PHYSICIAN1_SUGGESTION_ID, {
    claimId: PHYSICIAN1_CLAIM_ID,
    providerId: PHYSICIAN1_USER_ID,
  });

  // Physician 2 suggestions
  claimSuggestions.set(`${PHYSICIAN2_CLAIM_ID}:${PHYSICIAN2_USER_ID}`, [
    makeSuggestion(PHYSICIAN2_SUGGESTION_ID, RULE_ID, 'provider2-secret-detail'),
  ]);
  suggestionClaimIndex.set(PHYSICIAN2_SUGGESTION_ID, {
    claimId: PHYSICIAN2_CLAIM_ID,
    providerId: PHYSICIAN2_USER_ID,
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
        if (forceInternalError) throw new Error('Database connection failed: pg_hba.conf reject for host 10.0.0.1');
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
      updateClaimSuggestions: vi.fn(async () => {}),
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
    updateClaimSuggestions: vi.fn(async () => {}),
    applyClaimChanges: vi.fn(async () => {}),
    revalidateClaim: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => {}),
    recordDismissal: vi.fn(async () => {}),
  };

  const learningLoopDeps = {
    getProviderLearning: vi.fn(async () => ({
      suppressedCount: 2,
      topCategories: [{ category: 'MODIFIER_ADD', count: 10 }],
      acceptanceRate: 0.75,
      totalSuggestions: 20,
    })),
    unsuppressRule: vi.fn(async () => null),
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
    getRuleStats: vi.fn(async () => ({
      ruleId: RULE_ID,
      totalShown: 100,
      totalAccepted: 60,
      totalDismissed: 40,
      acceptanceRate: 0.6,
      suppressionCount: 2,
    })),
    getLearningStateSummary: vi.fn(async () => ({
      suppressedCount: 2,
      topCategories: [{ category: 'MODIFIER_ADD', count: 10 }],
      acceptanceRate: 0.75,
      totalSuggestions: 20,
    })),
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
    unsuppressRule: vi.fn(async () => null),
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
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

describe('Intelligence Extensions Data Leakage Prevention (Security)', () => {
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
    users.push({ userId: PHYSICIAN1_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' });
    sessions.push(makeSession(PHYSICIAN1_SESSION_ID, PHYSICIAN1_USER_ID, PHYSICIAN1_TOKEN_HASH));

    // Physician 2
    users.push({ userId: PHYSICIAN2_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' });
    sessions.push(makeSession(PHYSICIAN2_SESSION_ID, PHYSICIAN2_USER_ID, PHYSICIAN2_TOKEN_HASH));

    // Admin
    users.push({ userId: ADMIN_USER_ID, role: 'ADMIN', subscriptionStatus: 'ACTIVE' });
    sessions.push(makeSession(ADMIN_SESSION_ID, ADMIN_USER_ID, ADMIN_TOKEN_HASH));
  });

  // =========================================================================
  // Suggestion Data Cross-Provider Leakage
  // =========================================================================

  describe('Suggestion data does not leak cross-provider', () => {
    it('physician2 cannot see physician1 suggestion descriptions', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
      expect(res.body).not.toContain('provider1-secret-detail');
    });

    it('physician1 cannot see physician2 suggestion descriptions', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
      expect(res.body).not.toContain('provider2-secret-detail');
    });

    it('physician1 sees only their own data in suggestions', async () => {
      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN1_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(res.body).toContain('provider1-secret-detail');
      expect(res.body).not.toContain('provider2-secret-detail');
    });

    it('physician2 sees only their own data in suggestions', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${PHYSICIAN2_CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      expect(res.body).toContain('provider2-secret-detail');
      expect(res.body).not.toContain('provider1-secret-detail');
    });
  });

  // =========================================================================
  // No Technology Headers Exposed
  // =========================================================================

  describe('HTTP headers do not leak server information', () => {
    it('extension endpoints do not contain X-Powered-By header', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('extension endpoints do not contain Server version header', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.headers['server']).toBeUndefined();
    });

    it('SOMB analysis endpoint does not leak tech headers', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
        new_version: '2026-01',
      });
      expect(res.headers['x-powered-by']).toBeUndefined();
      expect(res.headers['server']).toBeUndefined();
    });

    it('activate rule endpoint does not leak tech headers', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, {
        is_active: true,
      });
      expect(res.headers['x-powered-by']).toBeUndefined();
      expect(res.headers['server']).toBeUndefined();
    });

    it('multiple extension endpoints consistently omit server headers', async () => {
      const endpoints = [
        { method: 'GET' as const, url: `/api/v1/intelligence/rules/${DUMMY_UUID}/stats` },
        { method: 'POST' as const, url: '/api/v1/intelligence/cohorts/recalculate' },
        { method: 'POST' as const, url: '/api/v1/intelligence/somb-change-analysis', payload: { old_version: '2025-12', new_version: '2026-01' } },
        { method: 'PUT' as const, url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`, payload: { is_active: false } },
      ];

      for (const endpoint of endpoints) {
        const res = await injectAs(ADMIN_TOKEN, endpoint.method, endpoint.url, endpoint.payload as any);
        expect(res.headers['x-powered-by']).toBeUndefined();
        expect(res.headers['server']).toBeUndefined();
      }
    });
  });

  // =========================================================================
  // Error Response Leakage
  // =========================================================================

  describe('Error responses do not leak internal details', () => {
    it('500 error on extension endpoint does not expose database details', async () => {
      forceInternalError = true;

      const res = await injectAs(
        PHYSICIAN1_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        {
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
        },
      );

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');

      const rawBody = res.body;
      expect(rawBody).not.toMatch(/postgres/i);
      expect(rawBody).not.toMatch(/drizzle/i);
      expect(rawBody).not.toMatch(/pg_hba/i);
      expect(rawBody).not.toContain('Database connection');
      expect(rawBody).not.toContain('10.0.0.1');
    });

    it('403 on extension endpoint does not expose admin guard internals', async () => {
      const res = await injectAs(PHYSICIAN1_TOKEN, 'POST', '/api/v1/intelligence/cohorts/recalculate');

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Insufficient permissions');
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
      const rawBody = res.body;
      expect(rawBody).not.toContain('requireAdmin');
      expect(rawBody).not.toContain('ADMIN');
    });

    it('404 on cross-provider suggestion accept does not leak IDs', async () => {
      const res = await injectAs(
        PHYSICIAN2_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${PHYSICIAN1_SUGGESTION_ID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_SUGGESTION_ID);
      expect(JSON.stringify(body)).not.toContain(PHYSICIAN1_USER_ID);
    });
  });

  // =========================================================================
  // Rule Stats Do Not Leak Provider PHI
  // =========================================================================

  describe('Rule stats do not leak provider PHI', () => {
    it('rule stats response contains only aggregate data', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);

      // May return data or null depending on stub, but check for safety
      const rawBody = res.body;
      expect(rawBody).not.toContain('firstName');
      expect(rawBody).not.toContain('lastName');
      expect(rawBody).not.toContain('dateOfBirth');
      expect(rawBody).not.toContain('phn');
      expect(rawBody).not.toContain('patientName');
    });
  });

  // =========================================================================
  // Error Shape Consistency
  // =========================================================================

  describe('Error response shape consistency on extension endpoints', () => {
    it('403 has consistent {error: {code, message}} shape', async () => {
      const res = await injectAs(PHYSICIAN1_TOKEN, 'POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
        new_version: '2026-01',
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('401 has consistent error shape on extension endpoints', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
    });
  });
});
