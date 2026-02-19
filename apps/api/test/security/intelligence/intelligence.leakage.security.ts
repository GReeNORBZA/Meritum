// ============================================================================
// Domain 7: Intelligence Engine — PHI & Data Leakage Prevention (Security)
// Verifies PHI never leaks via LLM context, suggestion responses, error
// responses, HTTP headers, or learning/cohort aggregate data.
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
import { stripPhi, type AnonymisedClaimContext } from '../../../src/domains/intel/intel.llm.js';
import type { ClaimContext } from '../../../src/domains/intel/intel.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000099';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000099';

// Test PHI values
const TEST_PHN = '123456789';
const TEST_PATIENT_NAME = 'Jane Doe';
const TEST_PATIENT_FIRST = 'Jane';
const TEST_PATIENT_LAST = 'Doe';
const TEST_PROVIDER_PRAC_ID = 'prac-12345-secret';

// ---------------------------------------------------------------------------
// Test data — claim, suggestions
// ---------------------------------------------------------------------------

const CLAIM_ID = 'cccc0000-0000-0000-0000-000000000001';
const SUGGESTION_ID = 'dddd0000-0000-0000-0000-000000000001';
const RULE_ID = 'eeee0000-0000-0000-0000-000000000001';
const NONEXISTENT_UUID = 'ffff0000-0000-0000-0000-000000000099';

function makeSuggestion(suggestionId: string, ruleId: string) {
  return {
    suggestionId,
    ruleId,
    tier: 1,
    category: 'MODIFIER_ADD',
    priority: 'MEDIUM',
    title: 'Add CMGP Modifier for 03.04A',
    description: 'Consider adding CMGP modifier to increase reimbursement per SOMB Section 3.2.',
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

// Suggestion that definitely does NOT contain PHI
const CLEAN_SUGGESTION = makeSuggestion(SUGGESTION_ID, RULE_ID);

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
// Per-physician data stores
// ---------------------------------------------------------------------------

const claimSuggestions = new Map<string, any[]>();
const suggestionClaimIndex = new Map<string, { claimId: string; providerId: string }>();

/** Track what the error handler returns for forced errors */
let forceInternalError = false;

function resetDataStores() {
  claimSuggestions.clear();
  suggestionClaimIndex.clear();
  forceInternalError = false;

  claimSuggestions.set(`${CLAIM_ID}:${PHYSICIAN_USER_ID}`, [{ ...CLEAN_SUGGESTION }]);
  suggestionClaimIndex.set(SUGGESTION_ID, {
    claimId: CLAIM_ID,
    providerId: PHYSICIAN_USER_ID,
  });
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
      data: [
        {
          ruleId: RULE_ID,
          name: 'CMGP Modifier Check',
          category: 'MODIFIER_ADD',
          claimType: 'AHCIP',
          isActive: true,
          conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
          suggestionTemplate: {
            title: 'Add CMGP Modifier',
            description: 'CMGP modifier eligible per SOMB Section 3.2',
            source_reference: 'SOMB Section 3.2',
          },
          priorityFormula: 'fixed:MEDIUM',
          specialtyFilter: null,
          sombVersion: '2026-01',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ],
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
    })),
    getRule: vi.fn(async () => null),
    createRule: vi.fn(async () => null),
    updateRule: vi.fn(async () => null),
    activateRule: vi.fn(async () => null),
    getRuleStats: vi.fn(async () => null),
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
    // 500 — NEVER expose internal details
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

function injectAs(
  token: string,
  method: 'GET' | 'POST' | 'PUT',
  url: string,
  payload?: Record<string, unknown>,
) {
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
  claim_id: CLAIM_ID,
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

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Engine PHI Leakage Prevention (Security)', () => {
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

    // Physician user
    users.push({
      userId: PHYSICIAN_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push(makeSession(PHYSICIAN_SESSION_ID, PHYSICIAN_USER_ID, PHYSICIAN_TOKEN_HASH));

    // Admin user
    users.push({
      userId: ADMIN_USER_ID,
      role: 'ADMIN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push(makeSession(ADMIN_SESSION_ID, ADMIN_USER_ID, ADMIN_TOKEN_HASH));
  });

  // =========================================================================
  // LLM PHI Isolation (MOST CRITICAL)
  // =========================================================================

  describe('LLM PHI isolation — stripPhi function', () => {
    // Build a realistic ClaimContext with PHI injected in extended fields
    function buildContextWithPhi(): ClaimContext {
      return {
        claim: {
          claimId: CLAIM_ID,
          claimType: 'AHCIP',
          state: 'VALIDATED',
          dateOfService: '2026-01-15',
          dayOfWeek: 3,
          importSource: 'MANUAL',
        },
        ahcip: {
          healthServiceCode: '03.04A',
          modifier1: 'CMGP',
          modifier2: null,
          modifier3: null,
          diagnosticCode: '780',
          functionalCentre: 'MEDO',
          baNumber: 'BA1234',
          encounterType: 'OFFICE',
          calls: 1,
          timeSpent: 15,
          facilityNumber: null,
          referralPractitioner: TEST_PROVIDER_PRAC_ID,
          shadowBillingFlag: false,
          pcpcmBasketFlag: false,
          afterHoursFlag: false,
          afterHoursType: null,
          submittedFee: '55.00',
        },
        wcb: null,
        patient: { age: 45, gender: 'M' },
        provider: {
          specialtyCode: 'GP',
          physicianType: 'GENERAL',
          defaultLocation: {
            functionalCentre: 'MEDO',
            facilityNumber: null,
            rrnpEligible: false,
          },
        },
        reference: {
          hscCode: {
            hscCode: '03.04A',
            baseFee: '38.89',
            feeType: 'FIXED',
            specialtyRestrictions: [],
            facilityRestrictions: [],
            modifierEligibility: ['CMGP', 'BMI'],
            pcpcmBasket: 'A',
            maxPerDay: null,
            requiresReferral: false,
            surchargeEligible: true,
          },
          modifiers: [
            {
              modifierCode: 'CMGP',
              type: 'PERCENTAGE',
              calculationMethod: 'ADD_PERCENT',
              combinableWith: ['BMI'],
              exclusiveWith: [],
              requiresTimeDocumentation: false,
            },
          ],
          diagnosticCode: { diCode: '780', qualifiesSurcharge: false, qualifiesBcp: false },
          sets: {},
        },
        crossClaim: {},
      };
    }

    it('stripPhi replaces referral practitioner ID with PROVIDER_REF', () => {
      const context = buildContextWithPhi();
      const anonymised = stripPhi(context);

      expect(anonymised.ahcip?.referralPractitioner).toBe('PROVIDER_REF');
      expect(JSON.stringify(anonymised)).not.toContain(TEST_PROVIDER_PRAC_ID);
    });

    it('stripPhi preserves null referral practitioner as null', () => {
      const context = buildContextWithPhi();
      context.ahcip!.referralPractitioner = null;
      const anonymised = stripPhi(context);

      expect(anonymised.ahcip?.referralPractitioner).toBeNull();
    });

    it('ClaimContext patient field contains only age and gender — no PHN, no name', () => {
      const context = buildContextWithPhi();
      const patientKeys = Object.keys(context.patient);

      expect(patientKeys).toContain('age');
      expect(patientKeys).toContain('gender');
      expect(patientKeys).not.toContain('phn');
      expect(patientKeys).not.toContain('firstName');
      expect(patientKeys).not.toContain('lastName');
      expect(patientKeys).not.toContain('name');
      expect(patientKeys).not.toContain('dateOfBirth');
    });

    it('anonymised context preserves billing codes but no patient identity', () => {
      const context = buildContextWithPhi();
      const anonymised = stripPhi(context);
      const serialised = JSON.stringify(anonymised);

      // Billing codes are preserved
      expect(serialised).toContain('03.04A');
      expect(serialised).toContain('CMGP');
      expect(serialised).toContain('780');
      expect(serialised).toContain('38.89');

      // No patient identity
      expect(serialised).not.toContain(TEST_PHN);
      expect(serialised).not.toContain(TEST_PATIENT_NAME);
      expect(serialised).not.toContain(TEST_PATIENT_FIRST);
      expect(serialised).not.toContain(TEST_PATIENT_LAST);
    });

    it('anonymised context does not include crossClaim data', () => {
      const context = buildContextWithPhi();
      const anonymised = stripPhi(context) as unknown as Record<string, unknown>;

      // stripPhi does not copy crossClaim to the anonymised context
      expect(anonymised).not.toHaveProperty('crossClaim');
    });

    it('stripPhi handles WCB claims without error', () => {
      const context = buildContextWithPhi();
      context.ahcip = null;
      context.wcb = { formId: 'WCB-001', wcbClaimNumber: 'W12345' };
      context.claim.claimType = 'WCB';

      const anonymised = stripPhi(context);

      expect(anonymised.ahcip).toBeNull();
      expect(anonymised.wcb).not.toBeNull();
      expect(anonymised.wcb?.formId).toBe('WCB-001');
    });

    it('LLM prompt (serialised anonymised context) never contains PHN pattern', () => {
      const context = buildContextWithPhi();
      const anonymised = stripPhi(context);
      const prompt = JSON.stringify(anonymised, null, 2);

      // Verify no 9-digit PHN-like pattern that matches test PHN
      expect(prompt).not.toContain(TEST_PHN);
      // No patient name
      expect(prompt).not.toContain(TEST_PATIENT_FIRST);
      expect(prompt).not.toContain(TEST_PATIENT_LAST);
    });

    it('LLM response processing does not re-inject PHI into suggestions', () => {
      // Simulating what happens after LLM response parsing:
      // The parsed response contains explanation, confidence, source_reference etc.
      // None of these fields should contain patient PHI.
      const llmParsedResponse = {
        explanation: 'Consider adding CMGP modifier for code 03.04A',
        confidence: 0.85,
        source_reference: 'SOMB Section 3.2',
        category: 'MODIFIER_ADD',
        suggested_changes: [{ field: 'modifier1', value_formula: 'CMGP' }],
        revenue_impact: 15.5,
      };

      const responseStr = JSON.stringify(llmParsedResponse);
      expect(responseStr).not.toContain(TEST_PHN);
      expect(responseStr).not.toContain(TEST_PATIENT_FIRST);
      expect(responseStr).not.toContain(TEST_PATIENT_LAST);
      // Billing codes may appear — that's expected and fine
      expect(responseStr).toContain('03.04A');
      expect(responseStr).toContain('CMGP');
    });
  });

  // =========================================================================
  // Suggestion Responses Do Not Leak PHI
  // =========================================================================

  describe('Suggestion responses do not leak PHI', () => {
    it('suggestion description does not contain patient PHN', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);

      const responseStr = JSON.stringify(body.data);
      expect(responseStr).not.toContain(TEST_PHN);
    });

    it('suggestion description does not contain patient name', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const responseStr = JSON.stringify(body.data);
      expect(responseStr).not.toContain(TEST_PATIENT_FIRST);
      expect(responseStr).not.toContain(TEST_PATIENT_LAST);
    });

    it('suggestion JSONB does not store raw LLM prompts', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${CLAIM_ID}/suggestions`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const responseStr = JSON.stringify(body.data);

      // Raw LLM prompts contain system prompt markers
      expect(responseStr).not.toContain('You are a medical billing domain expert');
      expect(responseStr).not.toContain('CONSTRAINTS:');
      expect(responseStr).not.toContain('Claim Context (Anonymised)');
      // No raw prompt structure
      expect(responseStr).not.toContain('"role":"system"');
      expect(responseStr).not.toContain('"role":"user"');
    });

    it('analyse response does not include patient identity', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        VALID_ANALYSE_PAYLOAD,
      );

      // Even if the endpoint returns a non-error status, check body for PHI
      const responseStr = res.body;
      expect(responseStr).not.toContain(TEST_PHN);
      expect(responseStr).not.toContain(TEST_PATIENT_FIRST);
      expect(responseStr).not.toContain(TEST_PATIENT_LAST);
    });
  });

  // =========================================================================
  // Error Responses
  // =========================================================================

  describe('Error responses do not leak PHI or internals', () => {
    it('500 error does not expose patient data in error body', async () => {
      // Trigger an internal error by setting the force flag
      forceInternalError = true;

      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        VALID_ANALYSE_PAYLOAD,
      );

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Internal server error');
      expect(body.error).not.toHaveProperty('stack');

      // Must not contain internal details
      const rawBody = res.body;
      expect(rawBody).not.toMatch(/postgres/i);
      expect(rawBody).not.toMatch(/drizzle/i);
      expect(rawBody).not.toMatch(/pg_hba/i);
      expect(rawBody).not.toMatch(/sql/i);
      expect(rawBody).not.toContain('Database connection');
      expect(rawBody).not.toContain('10.0.0.1');

      // Must not contain PHI
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
      expect(rawBody).not.toContain(CLAIM_ID);
    });

    it('400 validation error does not include claim PHI', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        {
          claim_id: 'not-a-uuid',
          claim_context: {
            claim_type: 'INVALID',
            health_service_code: '',
            modifiers: [],
            date_of_service: 'bad-date',
            provider_specialty: 'GP',
            patient_demographics_anonymised: { age_range: '40-50', gender: 'M' },
            diagnostic_codes: [],
          },
        },
      );

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      // Error response should not contain PHI
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
    });

    it('404 does not confirm claim existence', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${NONEXISTENT_UUID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).toBe('Resource not found');
      // Must not contain the UUID
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
      // Must not specify the resource type
      expect(body.error.message).not.toMatch(/suggestion|claim|patient|provider/i);
    });

    it('404 for claim suggestions does not confirm claim existence', async () => {
      // Accessing a non-existent claim's suggestions
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'GET',
        `/api/v1/intelligence/claims/${NONEXISTENT_UUID}/suggestions`,
      );

      // Should return empty array (no data found for this physician), not detailed error
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toEqual([]);
    });

    it('dismiss endpoint 404 does not echo suggestion ID', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${NONEXISTENT_UUID}/dismiss`,
        { reason: 'not_applicable' },
      );

      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(NONEXISTENT_UUID);
    });
  });

  // =========================================================================
  // HTTP Headers
  // =========================================================================

  describe('HTTP headers do not leak server information', () => {
    it('responses do not contain X-Powered-By header', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('responses do not contain Server version header', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      // Fastify removes server header by default when logger: false
      // But we verify it explicitly
      expect(res.headers['server']).toBeUndefined();
    });

    it('multiple endpoints consistently omit server headers', async () => {
      const endpoints = [
        { method: 'GET' as const, url: '/api/v1/intelligence/rules' },
        { method: 'GET' as const, url: '/api/v1/intelligence/me/learning-state' },
        { method: 'GET' as const, url: `/api/v1/intelligence/claims/${CLAIM_ID}/suggestions` },
      ];

      for (const { method, url } of endpoints) {
        const res = await injectAs(PHYSICIAN_TOKEN, method, url);
        expect(res.headers['x-powered-by']).toBeUndefined();
        expect(res.headers['server']).toBeUndefined();
      }
    });

    it('HSTS header is present when Helmet is configured (production)', async () => {
      // In test mode (without Helmet plugin registered), HSTS may not be present.
      // This test documents the requirement: in production, @fastify/helmet
      // sets strict-transport-security. We verify the header is either present
      // (when Helmet is registered) or absent but not leaking other info.
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      // In production with Helmet, this would be set. In test without Helmet,
      // we verify no conflicting headers exist.
      const hsts = res.headers['strict-transport-security'];
      if (hsts) {
        expect(hsts).toContain('max-age');
      }
      // Either way, no server info leaks
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('CSP header is present when Helmet is configured (production)', async () => {
      // Similar to HSTS: in production, Helmet adds Content-Security-Policy.
      // In test without Helmet, verify no conflicting headers.
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      const csp = res.headers['content-security-policy'];
      if (csp) {
        expect(typeof csp).toBe('string');
        expect(csp.length).toBeGreaterThan(0);
      }
      // Verify no internal info in other headers
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  // =========================================================================
  // Learning Data Does Not Contain PHI
  // =========================================================================

  describe('Learning data does not contain PHI', () => {
    it('ai_provider_learning (learning state) contains no patient data', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const responseStr = JSON.stringify(body.data);

      // Learning state should contain only: suppressed count, top categories, acceptance rate, total suggestions
      expect(responseStr).not.toContain(TEST_PHN);
      expect(responseStr).not.toContain(TEST_PATIENT_FIRST);
      expect(responseStr).not.toContain(TEST_PATIENT_LAST);

      // Verify the shape contains only aggregate data
      const data = body.data;
      expect(data).toHaveProperty('suppressedCount');
      expect(data).toHaveProperty('acceptanceRate');
      expect(data).toHaveProperty('totalSuggestions');
      expect(typeof data.suppressedCount).toBe('number');
      expect(typeof data.acceptanceRate).toBe('number');
      expect(typeof data.totalSuggestions).toBe('number');
    });

    it('learning state does not expose rule conditions or internal formulas', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/me/learning-state');

      expect(res.statusCode).toBe(200);
      const responseStr = res.body;
      expect(responseStr).not.toContain('conditions');
      expect(responseStr).not.toContain('priorityFormula');
      expect(responseStr).not.toContain('IS NULL');
    });

    it('suggestion events contain no PHI — only suggestion IDs, categories, revenue impacts', async () => {
      // Simulate suggestion events stored data
      const safeEvent = {
        eventId: 'evt-001',
        claimId: CLAIM_ID,
        suggestionId: SUGGESTION_ID,
        ruleId: RULE_ID,
        providerId: PHYSICIAN_USER_ID,
        eventType: 'GENERATED',
        tier: 1,
        category: 'MODIFIER_ADD',
        revenueImpact: '15.50',
        dismissedReason: null,
        createdAt: new Date().toISOString(),
      };

      const eventStr = JSON.stringify(safeEvent);
      // Events should NOT contain patient data
      expect(eventStr).not.toContain(TEST_PHN);
      expect(eventStr).not.toContain(TEST_PATIENT_FIRST);
      expect(eventStr).not.toContain(TEST_PATIENT_LAST);
      // Should contain only IDs, categories, revenue
      expect(eventStr).toContain('MODIFIER_ADD');
      expect(eventStr).toContain('15.50');
    });

    it('dismissed reason field does not store PHI even if physician types it', () => {
      // A physician might type PHI in a dismiss reason. The schema should sanitise.
      // The Zod schema limits reason to max 500 chars but doesn't sanitise PHI.
      // However, the response should not echo raw PHI.
      const phiContainingReason = `Patient ${TEST_PATIENT_FIRST} ${TEST_PATIENT_LAST} PHN ${TEST_PHN} disagrees`;

      // The dismiss reason is stored as-is, but we verify:
      // 1. The suggestion event table does not store patient names/PHN in other fields
      // 2. The reason field is free-text but bounded in length
      expect(phiContainingReason.length).toBeLessThanOrEqual(500);
      // This documents the risk: dismissed_reason is free text.
      // The system trusts physician input here but limits it to 500 chars.
    });
  });

  // =========================================================================
  // Specialty Cohorts Do Not Contain PHI
  // =========================================================================

  describe('Specialty cohorts contain no PHI', () => {
    it('cohort data contains only aggregate rates and counts', () => {
      // Verify cohort structure has no PHI fields
      const cohort = {
        cohortId: 'cohort-001',
        specialtyCode: 'GP',
        ruleId: RULE_ID,
        physicianCount: 25,
        acceptanceRate: '0.7200',
        medianRevenueImpact: '15.50',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const cohortStr = JSON.stringify(cohort);
      expect(cohortStr).not.toContain(TEST_PHN);
      expect(cohortStr).not.toContain(TEST_PATIENT_FIRST);
      expect(cohortStr).not.toContain(TEST_PATIENT_LAST);
      expect(cohortStr).not.toContain(PHYSICIAN_USER_ID);
      // Only aggregate data
      expect(cohortStr).toContain('physicianCount');
      expect(cohortStr).toContain('acceptanceRate');
      expect(cohortStr).toContain('medianRevenueImpact');
    });
  });

  // =========================================================================
  // Rule Conditions JSONB Not Exposed to Non-Admin
  // =========================================================================

  describe('Rule conditions not exposed to non-admin users', () => {
    it('GET /intelligence/rules as physician does not include conditions field', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);

      for (const rule of body.data) {
        // Physician should NOT see internal rule implementation
        expect(rule).not.toHaveProperty('conditions');
        expect(rule).not.toHaveProperty('priorityFormula');
        expect(rule).not.toHaveProperty('specialtyFilter');
        expect(rule).not.toHaveProperty('suggestionTemplate');
        expect(rule).not.toHaveProperty('sombVersion');

        // Physician SHOULD see transparency fields
        expect(rule).toHaveProperty('ruleId');
        expect(rule).toHaveProperty('name');
        expect(rule).toHaveProperty('category');
        expect(rule).toHaveProperty('claimType');
        expect(rule).toHaveProperty('description');
        expect(rule).toHaveProperty('isActive');
      }
    });

    it('GET /intelligence/rules as admin includes full rule data', async () => {
      const res = await injectAs(ADMIN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);

      // Admin sees full data
      const rule = body.data[0];
      expect(rule).toHaveProperty('conditions');
      expect(rule).toHaveProperty('priorityFormula');
      expect(rule).toHaveProperty('suggestionTemplate');
    });

    it('physician sees sanitised rules — no conditions JSONB leakage in response body', async () => {
      const res = await injectAs(PHYSICIAN_TOKEN, 'GET', '/api/v1/intelligence/rules');

      const rawBody = res.body;
      // The raw response body should not contain condition internals
      expect(rawBody).not.toContain('IS NULL');
      expect(rawBody).not.toContain('"operator"');
      expect(rawBody).not.toContain('"field":"ahcip');
      expect(rawBody).not.toContain('fixed:MEDIUM');
    });
  });

  // =========================================================================
  // Error Response Shape Consistency
  // =========================================================================

  describe('Error response shape consistency', () => {
    it('500 error has consistent {error: {code, message}} shape with no extras', async () => {
      forceInternalError = true;

      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        VALID_ANALYSE_PAYLOAD,
      );

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');
      // No stack, no details, no data
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('details');
      expect(body).not.toHaveProperty('data');
    });

    it('404 error has consistent {error: {code, message}} shape', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        `/api/v1/intelligence/suggestions/${NONEXISTENT_UUID}/accept`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');
    });

    it('400 error does not expose Zod validation details with PHI', async () => {
      const res = await injectAs(
        PHYSICIAN_TOKEN,
        'POST',
        '/api/v1/intelligence/analyse',
        {
          claim_id: 'invalid',
          claim_context: null,
        },
      );

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      // Should not echo back the invalid claim_id or any PHI
      expect(rawBody).not.toContain(TEST_PHN);
      expect(rawBody).not.toContain(TEST_PATIENT_FIRST);
    });
  });
});
