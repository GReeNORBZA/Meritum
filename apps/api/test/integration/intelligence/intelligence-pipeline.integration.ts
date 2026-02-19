// ============================================================================
// Domain 7: Intelligence Engine — Integration Tests
// Full analysis pipeline: Tier 1 + Tier 2 + Tier 3 + Learning Loop
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
import {
  type IntelHandlerDeps,
} from '../../../src/domains/intel/intel.handlers.js';
import {
  type AnalyseDeps,
  type LifecycleDeps,
  type LearningLoopDeps,
  type SombChangeDeps,
  type ClaimContextDeps,
  type Tier1Deps,
  type Suggestion,
  type ClaimContext,
  evaluateTier1Rules,
  analyseClaim,
  acceptSuggestion,
  dismissSuggestion,
  getClaimSuggestions,
  processRejectionFeedback,
  recalculateSpecialtyCohorts,
  getDefaultPriorityForNewProvider,
  analyseSombChange,
  generateTier3Suggestion,
  buildClaimContext,
} from '../../../src/domains/intel/intel.service.js';
import {
  type Tier2Deps,
  analyseTier2,
  type LlmClient,
  type ChatMessage,
  type ChatCompletionOptions,
  type ChatCompletionResult,
} from '../../../src/domains/intel/intel.llm.js';
import {
  SuggestionCategory,
  SuggestionPriority,
  SuggestionStatus,
  SuggestionEventType,
  SUPPRESSION_THRESHOLD,
  LLM_CONFIDENCE_THRESHOLD,
} from '@meritum/shared/constants/intelligence.constants.js';
import type {
  SelectAiRule,
  SelectAiProviderLearning,
  SuggestionTemplate,
  Condition,
} from '@meritum/shared/schemas/db/intelligence.schema.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '10000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

const PHYSICIAN2_USER_ID = '20000000-2222-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);

const ADMIN_USER_ID = '30000000-3333-0000-0000-000000000003';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Fixed test IDs
// ---------------------------------------------------------------------------

const CLAIM_ID_1 = '00000000-cccc-0000-0000-000000000001';
const CLAIM_ID_2 = '00000000-cccc-0000-0000-000000000002';
const PATIENT_ID_1 = '00000000-aaaa-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Rule factory helpers
// ---------------------------------------------------------------------------

let ruleCounter = 0;

function makeRule(overrides: Partial<SelectAiRule> = {}): SelectAiRule {
  ruleCounter++;
  return {
    ruleId: overrides.ruleId ?? crypto.randomUUID(),
    name: overrides.name ?? `test-rule-${ruleCounter}`,
    category: overrides.category ?? SuggestionCategory.MODIFIER_ADD,
    claimType: overrides.claimType ?? 'AHCIP',
    conditions: overrides.conditions ?? {
      type: 'existence',
      field: 'ahcip.modifier1',
      operator: 'IS NULL',
    },
    suggestionTemplate: overrides.suggestionTemplate ?? {
      title: 'Add CMGP modifier to {{hsc}}',
      description: 'CMGP modifier is eligible for {{ahcip.healthServiceCode}}',
      revenue_impact_formula: 'fixed:15.00',
      source_reference: 'SOMB Section 3.2',
      source_url: null,
      suggested_changes: [
        { field: 'modifier1', value_formula: 'CMGP' },
      ],
    },
    specialtyFilter: overrides.specialtyFilter ?? null,
    priorityFormula: overrides.priorityFormula ?? 'fixed:MEDIUM',
    isActive: overrides.isActive ?? true,
    sombVersion: overrides.sombVersion ?? '2026-01',
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  } as SelectAiRule;
}

function makeLearningState(overrides: Partial<SelectAiProviderLearning> = {}): SelectAiProviderLearning {
  return {
    learningId: overrides.learningId ?? crypto.randomUUID(),
    providerId: overrides.providerId ?? PHYSICIAN1_USER_ID,
    ruleId: overrides.ruleId ?? crypto.randomUUID(),
    timesShown: overrides.timesShown ?? 0,
    timesAccepted: overrides.timesAccepted ?? 0,
    timesDismissed: overrides.timesDismissed ?? 0,
    consecutiveDismissals: overrides.consecutiveDismissals ?? 0,
    isSuppressed: overrides.isSuppressed ?? false,
    priorityAdjustment: overrides.priorityAdjustment ?? 0,
    lastShownAt: overrides.lastShownAt ?? null,
    lastFeedbackAt: overrides.lastFeedbackAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  } as SelectAiProviderLearning;
}

// ---------------------------------------------------------------------------
// Mock ClaimContextDeps: returns a pre-built AHCIP claim context
// ---------------------------------------------------------------------------

function createMockClaimContextDeps(overrides: {
  claimType?: string;
  modifier1?: string | null;
  healthServiceCode?: string;
  specialtyCode?: string;
  crossClaimCount?: number;
} = {}): ClaimContextDeps {
  const claimType = overrides.claimType ?? 'AHCIP';
  return {
    getClaim: vi.fn(async (claimId: string, providerId: string) => ({
      claimId,
      claimType,
      state: 'DRAFT',
      dateOfService: '2026-01-15',
      importSource: 'MANUAL',
      patientId: PATIENT_ID_1,
    })),
    getAhcipDetails: vi.fn(async () =>
      claimType === 'AHCIP'
        ? {
            healthServiceCode: overrides.healthServiceCode ?? '03.04A',
            modifier1: overrides.modifier1 ?? null,
            modifier2: null,
            modifier3: null,
            diagnosticCode: null,
            functionalCentre: 'MEDI',
            baNumber: 'BA001',
            encounterType: 'OFFICE',
            calls: 1,
            timeSpent: null,
            facilityNumber: null,
            referralPractitioner: null,
            shadowBillingFlag: false,
            pcpcmBasketFlag: false,
            afterHoursFlag: false,
            afterHoursType: null,
            submittedFee: null,
          }
        : null,
    ),
    getWcbDetails: vi.fn(async () =>
      claimType === 'WCB'
        ? {
            formId: 'C050E',
            wcbClaimNumber: 'WCB-2026-001',
          }
        : null,
    ),
    getPatientDemographics: vi.fn(async () => ({
      dateOfBirth: '1980-06-15',
      gender: 'M',
    })),
    getProvider: vi.fn(async () => ({
      specialtyCode: overrides.specialtyCode ?? 'GP',
      physicianType: 'GENERAL',
    })),
    getDefaultLocation: vi.fn(async () => ({
      functionalCentre: 'MEDI',
      facilityNumber: null,
      rrnpEligible: false,
    })),
    getHscCode: vi.fn(async (hscCode: string) => ({
      hscCode,
      baseFee: '35.00',
      feeType: 'SERVICE_FEE',
      specialtyRestrictions: [],
      facilityRestrictions: [],
      modifierEligibility: ['CMGP', 'AFHR'],
      pcpcmBasket: 'NONE',
      maxPerDay: null,
      requiresReferral: false,
      surchargeEligible: false,
    })),
    getModifierDefinitions: vi.fn(async () => []),
    getDiCode: vi.fn(async () => null),
    getReferenceSet: vi.fn(async () => []),
    getCrossClaimCount: vi.fn(async () => overrides.crossClaimCount ?? 0),
    getCrossClaimSum: vi.fn(async () => 0),
    getCrossClaimExists: vi.fn(async () => false),
  };
}

// ---------------------------------------------------------------------------
// Mock Tier1Deps
// ---------------------------------------------------------------------------

function createMockTier1Deps(opts: {
  rules?: SelectAiRule[];
  learningStates?: SelectAiProviderLearning[];
} = {}): Tier1Deps {
  return {
    getActiveRulesForClaim: vi.fn(async () => opts.rules ?? []),
    getProviderLearningForRules: vi.fn(async () => opts.learningStates ?? []),
    incrementShown: vi.fn(async (providerId: string, ruleId: string) =>
      makeLearningState({ providerId, ruleId, timesShown: 1 }),
    ),
    appendSuggestionEvent: vi.fn(async () => ({})),
  };
}

// ---------------------------------------------------------------------------
// In-memory claim suggestion store (simulates JSONB on claims table)
// ---------------------------------------------------------------------------

function createSuggestionStore() {
  const store = new Map<string, Suggestion[]>();

  return {
    store,
    getClaimSuggestions: vi.fn(async (claimId: string, _providerId: string) =>
      store.get(claimId) ?? null,
    ),
    updateClaimSuggestions: vi.fn(async (claimId: string, _providerId: string, suggestions: Suggestion[]) => {
      store.set(claimId, suggestions);
    }),
    applyClaimChanges: vi.fn(async () => {}),
    revalidateClaim: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock LifecycleDeps with in-memory learning state
// ---------------------------------------------------------------------------

function createMockLifecycleDeps(suggestionStoreOverride?: ReturnType<typeof createSuggestionStore>) {
  const suggestionStore = suggestionStoreOverride ?? createSuggestionStore();
  const learningStore = new Map<string, SelectAiProviderLearning>();

  function learningKey(providerId: string, ruleId: string) {
    return `${providerId}:${ruleId}`;
  }

  function getOrCreateLearning(providerId: string, ruleId: string): SelectAiProviderLearning {
    const key = learningKey(providerId, ruleId);
    let state = learningStore.get(key);
    if (!state) {
      state = makeLearningState({ providerId, ruleId });
      learningStore.set(key, state);
    }
    return state;
  }

  const deps: LifecycleDeps = {
    getClaimSuggestions: suggestionStore.getClaimSuggestions,
    updateClaimSuggestions: suggestionStore.updateClaimSuggestions,
    applyClaimChanges: suggestionStore.applyClaimChanges,
    revalidateClaim: suggestionStore.revalidateClaim,
    appendSuggestionEvent: vi.fn(async () => ({})),
    recordAcceptance: vi.fn(async (providerId: string, ruleId: string) => {
      const state = getOrCreateLearning(providerId, ruleId);
      state.timesAccepted++;
      state.consecutiveDismissals = 0;
      state.isSuppressed = false;
      return state;
    }),
    recordDismissal: vi.fn(async (providerId: string, ruleId: string) => {
      const state = getOrCreateLearning(providerId, ruleId);
      state.timesDismissed++;
      state.consecutiveDismissals++;
      if (state.consecutiveDismissals >= SUPPRESSION_THRESHOLD) {
        state.isSuppressed = true;
      }
      return state;
    }),
  };

  return { deps, suggestionStore, learningStore, getOrCreateLearning };
}

// ---------------------------------------------------------------------------
// Mock LLM Client factory
// ---------------------------------------------------------------------------

function createMockLlmClient(opts: {
  confidence?: number;
  category?: string;
  shouldTimeout?: boolean;
  explanation?: string;
  sourceReference?: string;
  suggestedChanges?: { field: string; value_formula: string }[] | null;
  revenueImpact?: number | null;
} = {}): LlmClient {
  return {
    config: Object.freeze({
      baseUrl: 'http://mock-llm:8080',
      model: 'test-model',
      timeoutMs: 3000,
    }),
    chatCompletion: vi.fn(async (_messages: ChatMessage[], _options?: ChatCompletionOptions): Promise<ChatCompletionResult> => {
      if (opts.shouldTimeout) {
        throw new Error('LLM timeout');
      }

      const response = {
        explanation: opts.explanation ?? 'Consider adding eConsult modifier for this code',
        confidence: opts.confidence ?? 0.85,
        source_reference: opts.sourceReference ?? 'SOMB Section 4.1',
        category: opts.category ?? SuggestionCategory.CODE_ALTERNATIVE,
        revenue_impact: opts.revenueImpact ?? 12.50,
        suggested_changes: opts.suggestedChanges ?? [
          { field: 'modifier2', value_formula: 'ECON' },
        ],
      };

      return {
        content: JSON.stringify(response),
        finishReason: 'stop',
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock Tier2Deps
// ---------------------------------------------------------------------------

function createMockTier2Deps(llmClient: LlmClient | null = null): Tier2Deps {
  return {
    llmClient,
    referenceValidation: {
      findActiveVersion: vi.fn(async () => ({ versionId: 'v1' })),
      findRuleById: vi.fn(async () => ({ ruleId: 'GR1' })),
      findHscByCode: vi.fn(async () => ({ hscCode: '03.04A' })),
    },
    appendSuggestionEvent: vi.fn(async () => ({})),
  };
}

// ---------------------------------------------------------------------------
// Mock LearningLoopDeps (in-memory)
// ---------------------------------------------------------------------------

function createMockLearningLoopDeps() {
  const learningStore = new Map<string, SelectAiProviderLearning>();
  const eventStore: Array<{
    claimId: string;
    suggestionId: string;
    ruleId: string | null;
    providerId: string;
    eventType: string;
    tier: number;
    category: string;
    revenueImpact: string | null;
    dismissedReason: string | null;
    createdAt: Date;
    eventId: string;
  }> = [];

  function learningKey(providerId: string, ruleId: string) {
    return `${providerId}:${ruleId}`;
  }

  const deps: LearningLoopDeps = {
    getLearningState: vi.fn(async (providerId: string, ruleId: string) => {
      return learningStore.get(learningKey(providerId, ruleId)) ?? null;
    }),
    updatePriorityAdjustment: vi.fn(async (providerId: string, ruleId: string, adjustment: -1 | 0 | 1) => {
      const key = learningKey(providerId, ruleId);
      let state = learningStore.get(key);
      if (!state) {
        state = makeLearningState({ providerId, ruleId });
        learningStore.set(key, state);
      }
      state.priorityAdjustment = adjustment;
      return state;
    }),
    unsuppressRule: vi.fn(async (providerId: string, ruleId: string) => {
      const key = learningKey(providerId, ruleId);
      const state = learningStore.get(key);
      if (!state) return undefined;
      state.isSuppressed = false;
      state.consecutiveDismissals = 0;
      return state;
    }),
    getSuggestionEventsForClaim: vi.fn(async (claimId: string) => {
      return eventStore.filter((e) => e.claimId === claimId);
    }),
    appendSuggestionEvent: vi.fn(async (event: any) => {
      eventStore.push({
        ...event,
        eventId: crypto.randomUUID(),
        ruleId: event.ruleId ?? null,
        revenueImpact: event.revenueImpact ?? null,
        dismissedReason: event.dismissedReason ?? null,
        createdAt: new Date(),
      });
    }),
    getCohortDefaults: vi.fn(async () => null),
    recalculateAllCohorts: vi.fn(async () => []),
    deleteSmallCohorts: vi.fn(async () => 0),
  };

  return { deps, learningStore, eventStore, learningKey };
}

// ---------------------------------------------------------------------------
// Mock IntelRepository (for HTTP route tests)
// ---------------------------------------------------------------------------

function createMockIntelRepo() {
  return {
    listRules: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 50, hasMore: false },
    })),
    getRule: vi.fn(async () => undefined),
    createRule: vi.fn(async (data: any) => ({
      ruleId: crypto.randomUUID(),
      ...data,
      isActive: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    updateRule: vi.fn(async () => undefined),
    activateRule: vi.fn(async () => undefined),
    getRuleStats: vi.fn(async () => ({
      ruleId: '',
      totalShown: 0,
      totalAccepted: 0,
      totalDismissed: 0,
      acceptanceRate: 0,
      suppressionCount: 0,
    })),
    findClaimIdBySuggestionId: vi.fn(async () => null as string | null),
    getLearningStateSummary: vi.fn(async () => ({
      suppressedCount: 0,
      topAcceptedCategories: [],
      totalSuggestionsShown: 0,
      overallAcceptanceRate: 0,
    })),
  };
}

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === PHYSICIAN2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000002',
            userId: PHYSICIAN2_USER_ID,
            tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN2_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === ADMIN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000003',
            userId: ADMIN_USER_ID,
            tokenHash: ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: ADMIN_USER_ID,
            role: 'ADMIN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ============================================================================
// Test Suite 1: Tier 1 → Accept → Claim Updated
// ============================================================================

describe('Scenario 1: AHCIP claim → Tier 1 suggestions → accept → claim updated', () => {
  it('returns CMGP suggestion for AHCIP claim missing modifier and applies on accept', async () => {
    // Set up: AHCIP claim without CMGP modifier
    const cmgpRule = makeRule({
      name: 'CMGP modifier eligibility',
      category: SuggestionCategory.MODIFIER_ADD,
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
      suggestionTemplate: {
        title: 'Add CMGP modifier to {{ahcip.healthServiceCode}}',
        description: 'CMGP modifier is eligible for this service code',
        revenue_impact_formula: 'fixed:15.00',
        source_reference: 'SOMB Section 3.2',
        source_url: null,
        suggested_changes: [
          { field: 'modifier1', value_formula: 'CMGP' },
        ],
      } as SuggestionTemplate,
      priorityFormula: 'fixed:MEDIUM',
    });

    const contextDeps = createMockClaimContextDeps({ modifier1: null });
    const tier1Deps = createMockTier1Deps({ rules: [cmgpRule] });

    // 1. Run Tier 1 analysis
    const suggestions = await evaluateTier1Rules(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    // Assertions: CMGP suggestion returned
    expect(suggestions.length).toBe(1);
    expect(suggestions[0].category).toBe(SuggestionCategory.MODIFIER_ADD);
    expect(suggestions[0].suggestedChanges).toEqual([
      { field: 'modifier1', valueFormula: 'CMGP' },
    ]);
    expect(suggestions[0].revenueImpact).toBe(15.00);
    expect(suggestions[0].tier).toBe(1);
    expect(suggestions[0].confidence).toBe(1.0);

    // 2. Store suggestions on claim
    const { deps: lifecycleDeps, suggestionStore } = createMockLifecycleDeps();
    suggestions[0].status = SuggestionStatus.PENDING;
    suggestionStore.store.set(CLAIM_ID_1, suggestions);

    // 3. Accept the suggestion
    const accepted = await acceptSuggestion(
      CLAIM_ID_1,
      suggestions[0].suggestionId,
      PHYSICIAN1_USER_ID,
      lifecycleDeps,
    );

    // Assertions: suggestion accepted, changes applied
    expect(accepted).not.toBeNull();
    expect(accepted!.status).toBe(SuggestionStatus.ACCEPTED);
    expect(accepted!.resolvedBy).toBe(PHYSICIAN1_USER_ID);
    expect(accepted!.resolvedAt).toBeDefined();

    // applyClaimChanges was called with modifier1=CMGP
    expect(lifecycleDeps.applyClaimChanges).toHaveBeenCalledWith(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      [{ field: 'modifier1', valueFormula: 'CMGP' }],
    );

    // Revalidation was triggered
    expect(lifecycleDeps.revalidateClaim).toHaveBeenCalledWith(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
    );

    // ACCEPTED event logged
    expect(lifecycleDeps.appendSuggestionEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        claimId: CLAIM_ID_1,
        eventType: SuggestionEventType.ACCEPTED,
        category: SuggestionCategory.MODIFIER_ADD,
      }),
    );

    // Learning state updated
    expect(lifecycleDeps.recordAcceptance).toHaveBeenCalledWith(
      PHYSICIAN1_USER_ID,
      cmgpRule.ruleId,
    );
  });
});

// ============================================================================
// Test Suite 2: WCB Timing Suggestion
// ============================================================================

describe('Scenario 2: WCB claim approaching deadline → WCB_TIMING suggestion', () => {
  it('generates WCB_TIMING suggestion for C050E claim with approaching deadline', async () => {
    const wcbTimingRule = makeRule({
      name: 'WCB C050E timing tier warning',
      category: SuggestionCategory.WCB_TIMING,
      claimType: 'WCB',
      conditions: {
        type: 'and',
        children: [
          {
            type: 'field_compare',
            field: 'claim.claimType',
            operator: '==',
            value: 'WCB',
          },
          {
            type: 'field_compare',
            field: 'wcb.formId',
            operator: '==',
            value: 'C050E',
          },
        ],
      } as Condition,
      suggestionTemplate: {
        title: 'WCB C050E timing tier downgrade approaching',
        description: 'Submit C050E now for $94.15 same-day fee. On-time fee is $85.80. Late fee drops to $54.08.',
        revenue_impact_formula: 'fixed:8.35',
        source_reference: 'WCB Policy: C050E Fee Schedule',
        source_url: null,
        suggested_changes: null,
      } as SuggestionTemplate,
      priorityFormula: 'fixed:HIGH',
    });

    const contextDeps = createMockClaimContextDeps({ claimType: 'WCB' });
    const tier1Deps = createMockTier1Deps({ rules: [wcbTimingRule] });

    const suggestions = await evaluateTier1Rules(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    expect(suggestions.length).toBe(1);
    expect(suggestions[0].category).toBe(SuggestionCategory.WCB_TIMING);
    expect(suggestions[0].priority).toBe(SuggestionPriority.HIGH);
    expect(suggestions[0].description).toContain('$94.15');
    expect(suggestions[0].description).toContain('$85.80');
    expect(suggestions[0].description).toContain('$54.08');
    expect(suggestions[0].revenueImpact).toBe(8.35);
  });
});

// ============================================================================
// Test Suite 3: GR 3 Rejection Risk → Dismiss → Rejection → Feedback Loop
// ============================================================================

describe('Scenario 3: GR 3 rejection risk → dismiss → rejection → feedback loop', () => {
  it('processes rejection feedback and re-enables dismissed rule', async () => {
    const gr3Rule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000003',
      name: 'GR 3 visit limit exceeded',
      category: SuggestionCategory.REJECTION_RISK,
      conditions: {
        type: 'cross_claim',
        query: {
          lookbackDays: 365,
          field: 'visits',
          aggregation: 'count',
        },
        operator: '>',
        value: 3,
      } as Condition,
      suggestionTemplate: {
        title: 'GR 3 limit exceeded — high rejection risk',
        description: 'This patient has exceeded 3 visits for this code in the current period.',
        revenue_impact_formula: 'fixed:35.00',
        source_reference: 'GR 3',
        source_url: null,
        suggested_changes: null,
      } as SuggestionTemplate,
      priorityFormula: 'fixed:HIGH',
    });

    // 1. Analyse claim with cross-claim count > 3 (triggers GR 3 rule)
    const contextDeps = createMockClaimContextDeps({ crossClaimCount: 4 });
    const tier1Deps = createMockTier1Deps({ rules: [gr3Rule] });

    const suggestions = await evaluateTier1Rules(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    expect(suggestions.length).toBe(1);
    expect(suggestions[0].category).toBe(SuggestionCategory.REJECTION_RISK);

    // 2. Dismiss the suggestion
    const { deps: lifecycleDeps, suggestionStore, learningStore } = createMockLifecycleDeps();
    suggestions[0].status = SuggestionStatus.PENDING;
    suggestionStore.store.set(CLAIM_ID_1, suggestions);

    const dismissed = await dismissSuggestion(
      CLAIM_ID_1,
      suggestions[0].suggestionId,
      PHYSICIAN1_USER_ID,
      lifecycleDeps,
      'I know the patient history',
    );

    expect(dismissed).not.toBeNull();
    expect(dismissed!.status).toBe(SuggestionStatus.DISMISSED);
    expect(dismissed!.dismissedReason).toBe('I know the patient history');

    // 3. Simulate rejection feedback
    const { deps: learningLoopDeps, learningStore: llStore, eventStore } =
      createMockLearningLoopDeps();

    // Seed a suppressed learning state for the rule
    const key = `${PHYSICIAN1_USER_ID}:${gr3Rule.ruleId}`;
    llStore.set(key, makeLearningState({
      providerId: PHYSICIAN1_USER_ID,
      ruleId: gr3Rule.ruleId,
      isSuppressed: true,
      consecutiveDismissals: 5,
    }));

    // Seed a DISMISSED event for REJECTION_RISK
    eventStore.push({
      eventId: crypto.randomUUID(),
      claimId: CLAIM_ID_1,
      suggestionId: suggestions[0].suggestionId,
      ruleId: gr3Rule.ruleId,
      providerId: PHYSICIAN1_USER_ID,
      eventType: SuggestionEventType.DISMISSED,
      tier: 1,
      category: SuggestionCategory.REJECTION_RISK,
      revenueImpact: '35.00',
      dismissedReason: 'I know the patient history',
      createdAt: new Date(),
    });

    // Process rejection feedback
    const result = await processRejectionFeedback(
      CLAIM_ID_1,
      'GR 3 exceeded',
      learningLoopDeps,
    );

    // Assertions: rule re-enabled
    expect(result.processedRuleIds).toContain(gr3Rule.ruleId);

    // unsuppressRule was called (rule was suppressed)
    expect(learningLoopDeps.unsuppressRule).toHaveBeenCalledWith(
      PHYSICIAN1_USER_ID,
      gr3Rule.ruleId,
    );

    // Priority adjustment set to +1
    expect(learningLoopDeps.updatePriorityAdjustment).toHaveBeenCalledWith(
      PHYSICIAN1_USER_ID,
      gr3Rule.ruleId,
      1,
    );

    // REJECTION_FEEDBACK event logged
    expect(learningLoopDeps.appendSuggestionEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        claimId: CLAIM_ID_1,
        eventType: 'REJECTION_FEEDBACK',
        category: SuggestionCategory.REJECTION_RISK,
      }),
    );
  });
});

// ============================================================================
// Test Suite 4: Learning Loop Suppression
// ============================================================================

describe('Scenario 4: Dismiss same rule 5 times → suppressed → unsuppress → reappears', () => {
  it('suppresses rule after 5 consecutive dismissals and re-enables on unsuppress', async () => {
    const rule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000004',
      name: 'Test suppression rule',
    });

    const { deps: lifecycleDeps, suggestionStore, learningStore } = createMockLifecycleDeps();

    // Dismiss the same rule 5 times
    for (let i = 0; i < SUPPRESSION_THRESHOLD; i++) {
      const suggestion: Suggestion = {
        suggestionId: crypto.randomUUID(),
        ruleId: rule.ruleId,
        tier: 1,
        category: SuggestionCategory.MODIFIER_ADD,
        priority: SuggestionPriority.MEDIUM,
        title: `Suggestion ${i + 1}`,
        description: `Test suggestion ${i + 1}`,
        revenueImpact: 10.00,
        confidence: 1.0,
        sourceReference: 'SOMB',
        sourceUrl: null,
        suggestedChanges: null,
        status: SuggestionStatus.PENDING,
      };

      const claimId = `00000000-cccc-0000-0000-00000000000${i}`;
      suggestionStore.store.set(claimId, [suggestion]);

      await dismissSuggestion(
        claimId,
        suggestion.suggestionId,
        PHYSICIAN1_USER_ID,
        lifecycleDeps,
      );
    }

    // Verify recordDismissal called 5 times
    expect(lifecycleDeps.recordDismissal).toHaveBeenCalledTimes(SUPPRESSION_THRESHOLD);

    // The in-memory learning store should show suppression
    const key = `${PHYSICIAN1_USER_ID}:${rule.ruleId}`;
    const learningState = learningStore.get(key);
    expect(learningState).toBeDefined();
    expect(learningState!.isSuppressed).toBe(true);
    expect(learningState!.consecutiveDismissals).toBe(SUPPRESSION_THRESHOLD);

    // Now verify that Tier 1 evaluation skips suppressed rules
    const contextDeps = createMockClaimContextDeps();
    const tier1Deps = createMockTier1Deps({
      rules: [rule],
      learningStates: [learningState!],
    });

    const newSuggestions = await evaluateTier1Rules(
      CLAIM_ID_2,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    expect(newSuggestions.length).toBe(0);

    // Un-suppress the rule
    learningState!.isSuppressed = false;
    learningState!.consecutiveDismissals = 0;

    const tier1DepsAfterUnsuppress = createMockTier1Deps({
      rules: [rule],
      learningStates: [learningState!],
    });

    const suggestionsAfterUnsuppress = await evaluateTier1Rules(
      CLAIM_ID_2,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1DepsAfterUnsuppress,
    );

    // Rule should reappear
    expect(suggestionsAfterUnsuppress.length).toBe(1);
    expect(suggestionsAfterUnsuppress[0].ruleId).toBe(rule.ruleId);
  });
});

// ============================================================================
// Test Suite 5: Tier 2 LLM Analysis (mock)
// ============================================================================

describe('Scenario 5: Tier 2 LLM analysis returns CODE_ALTERNATIVE suggestion', () => {
  it('appends Tier 2 suggestion to claim JSONB after Tier 1', async () => {
    const mockLlm = createMockLlmClient({
      confidence: 0.85,
      category: SuggestionCategory.CODE_ALTERNATIVE,
      explanation: 'Consider using code 03.05A instead of 03.04A for this encounter type',
      sourceReference: 'SOMB Section 4.1',
      revenueImpact: 12.50,
      suggestedChanges: [
        { field: 'healthServiceCode', value_formula: '03.05A' },
      ],
    });

    const contextDeps = createMockClaimContextDeps();
    const context = await buildClaimContext(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
    );
    expect(context).not.toBeNull();

    const tier1Suggestions: Suggestion[] = [
      {
        suggestionId: crypto.randomUUID(),
        ruleId: 'tier1-rule-id',
        tier: 1,
        category: SuggestionCategory.MODIFIER_ADD,
        priority: SuggestionPriority.MEDIUM,
        title: 'Add CMGP',
        description: 'CMGP is eligible',
        revenueImpact: 15.00,
        confidence: 1.0,
        sourceReference: 'SOMB',
        sourceUrl: null,
        suggestedChanges: [{ field: 'modifier1', valueFormula: 'CMGP' }],
      },
    ];

    const tier2Deps = createMockTier2Deps(mockLlm);

    const tier2Suggestions = await analyseTier2(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      context!,
      tier1Suggestions,
      tier2Deps,
    );

    // Assertions: Tier 2 returned a CODE_ALTERNATIVE suggestion
    expect(tier2Suggestions.length).toBe(1);
    expect(tier2Suggestions[0].tier).toBe(2);
    expect(tier2Suggestions[0].category).toBe(SuggestionCategory.CODE_ALTERNATIVE);
    expect(tier2Suggestions[0].confidence).toBe(0.85);
    expect(tier2Suggestions[0].description).toContain('03.05A');
    expect(tier2Suggestions[0].suggestedChanges).toBeDefined();

    // Verify event was logged
    expect(tier2Deps.appendSuggestionEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        claimId: CLAIM_ID_1,
        eventType: SuggestionEventType.GENERATED,
        tier: 2,
        category: SuggestionCategory.CODE_ALTERNATIVE,
      }),
    );
  });
});

// ============================================================================
// Test Suite 6: Tier 2 Timeout Fallback
// ============================================================================

describe('Scenario 6: Tier 2 timeout → Tier 1 delivered → no error', () => {
  it('returns empty array on LLM timeout without errors', async () => {
    const timeoutLlm = createMockLlmClient({ shouldTimeout: true });

    const contextDeps = createMockClaimContextDeps();
    const context = await buildClaimContext(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
    );

    const tier2Deps = createMockTier2Deps(timeoutLlm);

    const tier2Suggestions = await analyseTier2(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      context!,
      [],
      tier2Deps,
    );

    // Graceful degradation: empty result, no error thrown
    expect(tier2Suggestions).toEqual([]);
  });

  it('full analyseClaim returns Tier 1 results even when Tier 2 times out', async () => {
    const cmgpRule = makeRule({
      category: SuggestionCategory.MODIFIER_ADD,
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
    });

    const contextDeps = createMockClaimContextDeps();
    const tier1Deps = createMockTier1Deps({ rules: [cmgpRule] });
    const timeoutLlm = createMockLlmClient({ shouldTimeout: true });
    const tier2Deps = createMockTier2Deps(timeoutLlm);
    const { deps: lifecycleDeps, suggestionStore } = createMockLifecycleDeps();

    const analyseDeps: AnalyseDeps = {
      contextDeps,
      tier1Deps,
      tier2Deps,
      lifecycleDeps,
      auditLog: vi.fn(async () => {}),
    };

    const result = await analyseClaim(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      analyseDeps,
    );

    // Tier 1 suggestions delivered
    expect(result.length).toBe(1);
    expect(result[0].category).toBe(SuggestionCategory.MODIFIER_ADD);
    expect(result[0].status).toBe(SuggestionStatus.PENDING);

    // Suggestions stored on claim
    const stored = suggestionStore.store.get(CLAIM_ID_1);
    expect(stored).toBeDefined();
    expect(stored!.length).toBe(1);
  });
});

// ============================================================================
// Test Suite 7: Tier 3 Escalation
// ============================================================================

describe('Scenario 7: LLM confidence below threshold → Tier 3 escalation', () => {
  it('routes low-confidence LLM response to Tier 3 REVIEW_RECOMMENDED', async () => {
    const lowConfLlm = createMockLlmClient({
      confidence: 0.45,
      explanation: 'The interaction between GR 3 and modifier CMGP is ambiguous for this case',
      sourceReference: 'GR 3',
    });

    const contextDeps = createMockClaimContextDeps();
    const context = await buildClaimContext(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
    );

    const tier2Deps = createMockTier2Deps(lowConfLlm);

    const suggestions = await analyseTier2(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      context!,
      [],
      tier2Deps,
    );

    // Assertions: Tier 3 suggestion returned
    expect(suggestions.length).toBe(1);
    expect(suggestions[0].tier).toBe(3);
    expect(suggestions[0].category).toBe(SuggestionCategory.REVIEW_RECOMMENDED);
    expect(suggestions[0].confidence).toBe(0.45);
    expect(suggestions[0].sourceReference).toBe('GR 3');
    // Tier 3 has no suggested_changes (cannot auto-accept)
    expect(suggestions[0].suggestedChanges).toBeNull();
  });

  it('generateTier3Suggestion creates proper structure with source link', () => {
    const contextDeps = createMockClaimContextDeps();

    // Build a minimal context for the function
    const context: ClaimContext = {
      claim: {
        claimId: CLAIM_ID_1,
        claimType: 'AHCIP',
        state: 'DRAFT',
        dateOfService: '2026-01-15',
        dayOfWeek: 3,
        importSource: 'MANUAL',
      },
      ahcip: {
        healthServiceCode: '03.04A',
        modifier1: null,
        modifier2: null,
        modifier3: null,
        diagnosticCode: null,
        functionalCentre: 'MEDI',
        baNumber: 'BA001',
        encounterType: 'OFFICE',
        calls: 1,
        timeSpent: null,
        facilityNumber: null,
        referralPractitioner: null,
        shadowBillingFlag: false,
        pcpcmBasketFlag: false,
        afterHoursFlag: false,
        afterHoursType: null,
        submittedFee: null,
      },
      wcb: null,
      patient: { age: 45, gender: 'M' },
      provider: {
        specialtyCode: 'GP',
        physicianType: 'GENERAL',
        defaultLocation: null,
      },
      reference: {
        hscCode: null,
        modifiers: [],
        diagnosticCode: null,
        sets: {},
      },
      crossClaim: {},
    };

    const suggestion = generateTier3Suggestion(
      'llm_low_confidence',
      context,
      'GR 3',
      'https://somb.alberta.ca/gr3',
    );

    expect(suggestion.tier).toBe(3);
    expect(suggestion.category).toBe(SuggestionCategory.REVIEW_RECOMMENDED);
    expect(suggestion.suggestedChanges).toBeNull();
    expect(suggestion.confidence).toBeNull();
    expect(suggestion.revenueImpact).toBeNull();
    expect(suggestion.sourceReference).toBe('GR 3');
    expect(suggestion.sourceUrl).toBe('https://somb.alberta.ca/gr3');
    expect(suggestion.title).toContain('Review recommended');
    expect(suggestion.title).toContain('03.04A');
  });
});

// ============================================================================
// Test Suite 8: Specialty Cohort Initialization
// ============================================================================

describe('Scenario 8: Specialty cohort defaults for new provider', () => {
  it('new physician inherits priority adjustment from cohort with high acceptance rate', async () => {
    const ruleId = crypto.randomUUID();

    const { deps: learningLoopDeps } = createMockLearningLoopDeps();

    // Mock cohort with >70% acceptance rate → priority +1
    (learningLoopDeps.getCohortDefaults as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      cohortId: crypto.randomUUID(),
      specialtyCode: 'GP',
      ruleId,
      physicianCount: 15,
      acceptanceRate: '0.8500',
      medianRevenueImpact: '12.50',
      updatedAt: new Date(),
    });

    const adjustment = await getDefaultPriorityForNewProvider(
      'GP',
      ruleId,
      learningLoopDeps,
    );

    expect(adjustment).toBe(1);
  });

  it('new physician gets -1 from cohort with low acceptance rate', async () => {
    const ruleId = crypto.randomUUID();

    const { deps: learningLoopDeps } = createMockLearningLoopDeps();

    // Mock cohort with <30% acceptance rate → priority -1
    (learningLoopDeps.getCohortDefaults as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      cohortId: crypto.randomUUID(),
      specialtyCode: 'GP',
      ruleId,
      physicianCount: 12,
      acceptanceRate: '0.2000',
      medianRevenueImpact: '5.00',
      updatedAt: new Date(),
    });

    const adjustment = await getDefaultPriorityForNewProvider(
      'GP',
      ruleId,
      learningLoopDeps,
    );

    expect(adjustment).toBe(-1);
  });

  it('returns 0 when no qualifying cohort exists', async () => {
    const ruleId = crypto.randomUUID();

    const { deps: learningLoopDeps } = createMockLearningLoopDeps();

    // No cohort (default mock returns null)
    const adjustment = await getDefaultPriorityForNewProvider(
      'DERMATOLOGY',
      ruleId,
      learningLoopDeps,
    );

    expect(adjustment).toBe(0);
  });

  it('recalculates cohorts and deletes small ones', async () => {
    const { deps: learningLoopDeps } = createMockLearningLoopDeps();

    // Mock recalculation returning some cohorts
    const cohortData = [
      {
        cohortId: crypto.randomUUID(),
        specialtyCode: 'GP',
        ruleId: crypto.randomUUID(),
        physicianCount: 15,
        acceptanceRate: '0.7500',
        medianRevenueImpact: '10.00',
        updatedAt: new Date(),
      },
      {
        cohortId: crypto.randomUUID(),
        specialtyCode: 'IM',
        ruleId: crypto.randomUUID(),
        physicianCount: 20,
        acceptanceRate: '0.5000',
        medianRevenueImpact: '8.00',
        updatedAt: new Date(),
      },
    ];

    (learningLoopDeps.recalculateAllCohorts as ReturnType<typeof vi.fn>).mockResolvedValueOnce(cohortData);
    (learningLoopDeps.deleteSmallCohorts as ReturnType<typeof vi.fn>).mockResolvedValueOnce(3);

    const result = await recalculateSpecialtyCohorts({
      recalculateAllCohorts: learningLoopDeps.recalculateAllCohorts,
      deleteSmallCohorts: learningLoopDeps.deleteSmallCohorts,
    });

    expect(result.cohorts.length).toBe(2);
    expect(result.cohorts[0].specialtyCode).toBe('GP');
    expect(result.cohorts[1].specialtyCode).toBe('IM');
    expect(result.deletedCount).toBe(3);
    expect(learningLoopDeps.deleteSmallCohorts).toHaveBeenCalledWith(10);
  });
});

// ============================================================================
// Test Suite 9: SOMB Version Change Analysis
// ============================================================================

describe('Scenario 9: SOMB version change → impact analysis', () => {
  it('identifies affected physicians and generates impact summaries', async () => {
    const ruleOldOnly = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000901',
      name: 'Deprecated modifier rule',
      category: SuggestionCategory.MODIFIER_ADD,
      sombVersion: '2025-Q4',
    });

    const ruleUpdated = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000902',
      name: 'Updated fee rule',
      category: SuggestionCategory.FEE_OPTIMISATION,
      sombVersion: '2025-Q4',
      conditions: {
        type: 'field_compare',
        field: 'ahcip.healthServiceCode',
        operator: '==',
        value: '03.04A',
      } as Condition,
    });

    const ruleUpdatedNew = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000903',
      name: 'Updated fee rule',
      category: SuggestionCategory.FEE_OPTIMISATION,
      sombVersion: '2026-Q1',
      conditions: {
        type: 'field_compare',
        field: 'ahcip.healthServiceCode',
        operator: '==',
        value: '03.04B',
      } as Condition,
    });

    const ruleNew = makeRule({
      ruleId: '00000000-rule-0000-0000-000000000904',
      name: 'Brand new rule',
      category: SuggestionCategory.CODE_ALTERNATIVE,
      sombVersion: '2026-Q1',
    });

    const sombChangeDeps: SombChangeDeps = {
      getRulesByVersion: vi.fn(async (version: string) => {
        if (version === '2025-Q4') return [ruleOldOnly, ruleUpdated];
        if (version === '2026-Q1') return [ruleUpdatedNew, ruleNew];
        return [];
      }),
      getProviderLearningForRules: vi.fn(async (providerId: string, ruleIds: string[]) => {
        // Physician1 used both old rules
        if (providerId === PHYSICIAN1_USER_ID) {
          return ruleIds.map((ruleId) =>
            makeLearningState({ providerId, ruleId, timesShown: 5 }),
          );
        }
        return [];
      }),
      getPhysiciansUsingRules: vi.fn(async () => [
        { providerId: PHYSICIAN1_USER_ID },
        { providerId: PHYSICIAN2_USER_ID },
      ]),
      emitNotification: vi.fn(async () => {}),
    };

    const result = await analyseSombChange('2025-Q4', '2026-Q1', sombChangeDeps);

    // Assertions: affected rules identified
    expect(result.totalAffectedRules).toBeGreaterThanOrEqual(2); // deprecated + updated + new

    // Physician1 was affected (had learning data)
    expect(result.totalAffectedPhysicians).toBeGreaterThanOrEqual(1);

    const p1Impact = result.physicianImpacts.find(
      (p) => p.providerId === PHYSICIAN1_USER_ID,
    );
    expect(p1Impact).toBeDefined();
    expect(p1Impact!.affectedRules.length).toBeGreaterThan(0);
    expect(p1Impact!.plainLanguageSummary).toBeTruthy();

    // Deprecated rule was identified
    const deprecatedRule = p1Impact!.affectedRules.find(
      (r) => r.changeType === 'deprecated',
    );
    expect(deprecatedRule).toBeDefined();
    expect(deprecatedRule!.name).toBe('Deprecated modifier rule');

    // Notification was emitted for affected physician
    expect(sombChangeDeps.emitNotification).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'SOMB_CHANGE_IMPACT',
        physicianId: PHYSICIAN1_USER_ID,
      }),
    );
  });
});

// ============================================================================
// Test Suite 10: Multiple Rules on Same Claim
// ============================================================================

describe('Scenario 10: Multiple rules fire on same claim → priority order, no duplicates', () => {
  it('returns 3 distinct suggestions sorted by priority then revenue impact', async () => {
    const cmgpRule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000001001',
      name: 'CMGP modifier',
      category: SuggestionCategory.MODIFIER_ADD,
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
      suggestionTemplate: {
        title: 'Add CMGP modifier',
        description: 'CMGP is eligible',
        revenue_impact_formula: 'fixed:15.00',
        source_reference: 'SOMB Section 3.2',
        suggested_changes: [
          { field: 'modifier1', value_formula: 'CMGP' },
        ],
      } as SuggestionTemplate,
      priorityFormula: 'fixed:MEDIUM',
    });

    const gr3Rule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000001002',
      name: 'GR 3 limit warning',
      category: SuggestionCategory.REJECTION_RISK,
      conditions: {
        type: 'cross_claim',
        query: {
          lookbackDays: 365,
          field: 'visits',
          aggregation: 'count',
        },
        operator: '>',
        value: 3,
      } as Condition,
      suggestionTemplate: {
        title: 'GR 3 limit exceeded',
        description: 'High rejection risk',
        revenue_impact_formula: 'fixed:35.00',
        source_reference: 'GR 3',
        suggested_changes: null,
      } as SuggestionTemplate,
      priorityFormula: 'fixed:HIGH',
    });

    const diCodeRule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000001003',
      name: 'Missing DI code',
      category: SuggestionCategory.DOCUMENTATION_GAP,
      conditions: {
        type: 'existence',
        field: 'ahcip.diagnosticCode',
        operator: 'IS NULL',
      },
      suggestionTemplate: {
        title: 'Add diagnostic code',
        description: 'DI code improves claim acceptance',
        revenue_impact_formula: 'fixed:5.00',
        source_reference: 'SOMB Section 2.1',
        suggested_changes: [
          { field: 'diagnosticCode', value_formula: '780' },
        ],
      } as SuggestionTemplate,
      priorityFormula: 'fixed:LOW',
    });

    const contextDeps = createMockClaimContextDeps({
      modifier1: null,
      crossClaimCount: 4,
    });
    const tier1Deps = createMockTier1Deps({
      rules: [cmgpRule, gr3Rule, diCodeRule],
    });

    const suggestions = await evaluateTier1Rules(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    // 3 distinct suggestions returned
    expect(suggestions.length).toBe(3);

    // Sorted by priority: HIGH first, then MEDIUM, then LOW
    expect(suggestions[0].priority).toBe(SuggestionPriority.HIGH);
    expect(suggestions[0].category).toBe(SuggestionCategory.REJECTION_RISK);

    expect(suggestions[1].priority).toBe(SuggestionPriority.MEDIUM);
    expect(suggestions[1].category).toBe(SuggestionCategory.MODIFIER_ADD);

    expect(suggestions[2].priority).toBe(SuggestionPriority.LOW);
    expect(suggestions[2].category).toBe(SuggestionCategory.DOCUMENTATION_GAP);

    // No duplicate categories should exist when targeting different fields
    const categories = suggestions.map((s) => s.category);
    expect(new Set(categories).size).toBe(3);

    // Revenue impacts correct
    expect(suggestions[0].revenueImpact).toBe(35.00);
    expect(suggestions[1].revenueImpact).toBe(15.00);
    expect(suggestions[2].revenueImpact).toBe(5.00);
  });

  it('deduplicates suggestions targeting the same field (keeps highest priority)', async () => {
    const lowPriorityRule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000001010',
      name: 'Low priority modifier1',
      category: SuggestionCategory.MODIFIER_ADD,
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
      suggestionTemplate: {
        title: 'Add modifier (low)',
        description: 'Low priority modifier suggestion',
        revenue_impact_formula: 'fixed:5.00',
        source_reference: 'SOMB',
        suggested_changes: [
          { field: 'modifier1', value_formula: 'LOW_MOD' },
        ],
      } as SuggestionTemplate,
      priorityFormula: 'fixed:LOW',
    });

    const highPriorityRule = makeRule({
      ruleId: '00000000-rule-0000-0000-000000001011',
      name: 'High priority modifier1',
      category: SuggestionCategory.MODIFIER_ADD,
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
      suggestionTemplate: {
        title: 'Add modifier (high)',
        description: 'High priority modifier suggestion',
        revenue_impact_formula: 'fixed:25.00',
        source_reference: 'SOMB',
        suggested_changes: [
          { field: 'modifier1', value_formula: 'HIGH_MOD' },
        ],
      } as SuggestionTemplate,
      priorityFormula: 'fixed:HIGH',
    });

    const contextDeps = createMockClaimContextDeps({ modifier1: null });
    const tier1Deps = createMockTier1Deps({
      rules: [lowPriorityRule, highPriorityRule],
    });

    const suggestions = await evaluateTier1Rules(
      CLAIM_ID_1,
      PHYSICIAN1_USER_ID,
      contextDeps,
      tier1Deps,
    );

    // Only 1 suggestion (deduped on field 'modifier1')
    expect(suggestions.length).toBe(1);
    expect(suggestions[0].priority).toBe(SuggestionPriority.HIGH);
    expect(suggestions[0].suggestedChanges![0].valueFormula).toBe('HIGH_MOD');
  });
});

// ============================================================================
// Test Suite: Full Analysis Pipeline via HTTP Routes
// ============================================================================

describe('Intelligence HTTP routes: full pipeline', () => {
  let app: FastifyInstance;
  let mockRepo: ReturnType<typeof createMockIntelRepo>;
  let suggestionStore: ReturnType<typeof createSuggestionStore>;
  let mockAnalyseDeps: AnalyseDeps;
  let mockLifecycleDeps: LifecycleDeps;

  beforeAll(async () => {
    const cmgpRule = makeRule({
      name: 'CMGP eligible',
      conditions: {
        type: 'existence',
        field: 'ahcip.modifier1',
        operator: 'IS NULL',
      },
    });

    const contextDeps = createMockClaimContextDeps();
    const tier1Deps = createMockTier1Deps({ rules: [cmgpRule] });
    const tier2Deps = createMockTier2Deps(null);

    suggestionStore = createSuggestionStore();
    const lifecycle = createMockLifecycleDeps(suggestionStore);
    mockLifecycleDeps = lifecycle.deps;

    mockAnalyseDeps = {
      contextDeps,
      tier1Deps,
      tier2Deps,
      lifecycleDeps: mockLifecycleDeps,
      auditLog: vi.fn(async () => {}),
    };

    const learningLoopDeps: LearningLoopDeps = {
      getLearningState: vi.fn(async () => null),
      updatePriorityAdjustment: vi.fn(async () => undefined),
      unsuppressRule: vi.fn(async () => undefined),
      getSuggestionEventsForClaim: vi.fn(async () => []),
      appendSuggestionEvent: vi.fn(async () => ({})),
      getCohortDefaults: vi.fn(async () => null),
      recalculateAllCohorts: vi.fn(async () => []),
      deleteSmallCohorts: vi.fn(async () => 0),
    };

    mockRepo = createMockIntelRepo();

    const handlerDeps: IntelHandlerDeps = {
      analyseDeps: mockAnalyseDeps,
      lifecycleDeps: mockLifecycleDeps,
      learningLoopDeps,
      repo: mockRepo as any,
      auditLog: vi.fn(async () => {}),
    };

    app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    const mockSessionRepo = createMockSessionRepo();
    await app.register(authPluginFp, {
      sessionDeps: {
        sessionRepo: mockSessionRepo,
        auditRepo: { appendAuditLog: vi.fn() },
        events: { emit: vi.fn() },
      },
    });

    app.setErrorHandler((error, _request, reply) => {
      if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
        const statusCode = (error as any).statusCode ?? 500;
        if (statusCode >= 400 && statusCode < 500) {
          return reply.code(statusCode).send({
            error: {
              code: (error as any).code,
              message: error.message,
              details: (error as any).details,
            },
          });
        }
      }
      if (error.validation) {
        return reply.code(400).send({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Validation failed',
            details: error.validation,
          },
        });
      }
      return reply.code(500).send({
        error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
      });
    });

    await app.register(intelRoutes, { deps: handlerDeps });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    suggestionStore.store.clear();
  });

  function authedPost(url: string, body?: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
    return app.inject({
      method: 'POST',
      url,
      headers: {
        cookie: `session=${token}`,
        'content-type': 'application/json',
      },
      payload: body ?? {},
    });
  }

  function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
    return app.inject({
      method: 'GET',
      url,
      headers: { cookie: `session=${token}` },
    });
  }

  function authedPut(url: string, body: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
    return app.inject({
      method: 'PUT',
      url,
      headers: {
        cookie: `session=${token}`,
        'content-type': 'application/json',
      },
      payload: body,
    });
  }

  // --- POST /api/v1/intelligence/analyse ---
  it('POST /analyse returns 200 with suggestions', async () => {
    const res = await authedPost('/api/v1/intelligence/analyse', {
      claim_id: CLAIM_ID_1,
      claim_context: {
        claim_type: 'AHCIP',
        health_service_code: '03.04A',
        modifiers: [],
        date_of_service: '2026-01-15',
        provider_specialty: 'GP',
        patient_demographics_anonymised: { age_range: '40-50', gender: 'M' },
        diagnostic_codes: [],
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(Array.isArray(body.data)).toBe(true);
  });

  // --- POST /analyse validation ---
  it('POST /analyse rejects invalid claim_id', async () => {
    const res = await authedPost('/api/v1/intelligence/analyse', {
      claim_id: 'not-a-uuid',
      claim_context: {
        claim_type: 'AHCIP',
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
        provider_specialty: 'GP',
        patient_demographics_anonymised: {},
      },
    });

    expect(res.statusCode).toBe(400);
  });

  // --- GET /claims/:id/suggestions ---
  it('GET /claims/:claim_id/suggestions returns stored suggestions', async () => {
    const storedSuggestion: Suggestion = {
      suggestionId: crypto.randomUUID(),
      ruleId: 'test',
      tier: 1,
      category: SuggestionCategory.MODIFIER_ADD,
      priority: SuggestionPriority.MEDIUM,
      title: 'Test suggestion',
      description: 'A test',
      revenueImpact: 10.00,
      confidence: 1.0,
      sourceReference: 'SOMB',
      sourceUrl: null,
      suggestedChanges: null,
      status: SuggestionStatus.PENDING,
    };
    suggestionStore.store.set(CLAIM_ID_1, [storedSuggestion]);

    const res = await authedGet(`/api/v1/intelligence/claims/${CLAIM_ID_1}/suggestions`);

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.length).toBe(1);
  });

  // --- GET /me/learning-state ---
  it('GET /me/learning-state returns learning summary', async () => {
    const res = await authedGet('/api/v1/intelligence/me/learning-state');
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(body.data).toHaveProperty('suppressedCount');
    expect(body.data).toHaveProperty('totalSuggestionsShown');
  });

  // --- PUT /me/preferences ---
  it('PUT /me/preferences updates AI Coach preferences', async () => {
    const res = await authedPut(
      '/api/v1/intelligence/me/preferences',
      {
        enabled_categories: [SuggestionCategory.MODIFIER_ADD],
        disabled_categories: [SuggestionCategory.DOCUMENTATION_GAP],
      },
    );

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(body.data.enabledCategories).toContain(SuggestionCategory.MODIFIER_ADD);
  });

  // --- GET /rules (physician transparency) ---
  it('GET /rules returns sanitised list for physician', async () => {
    mockRepo.listRules.mockResolvedValueOnce({
      data: [makeRule({ name: 'Public rule' })],
      pagination: { total: 1, page: 1, pageSize: 50, hasMore: false },
    });

    const res = await authedGet('/api/v1/intelligence/rules');
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data.length).toBe(1);
    // Physician should NOT see conditions (stripped)
    expect(body.data[0].conditions).toBeUndefined();
    expect(body.data[0].name).toBe('Public rule');
  });

  // --- POST /rules (admin only) ---
  it('POST /rules returns 403 for non-admin', async () => {
    const res = await authedPost(
      '/api/v1/intelligence/rules',
      {
        name: 'New rule',
        category: SuggestionCategory.MODIFIER_ADD,
        claim_type: 'AHCIP',
        conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
        suggestion_template: {
          title: 'Test',
          description: 'Test description',
          source_reference: 'SOMB',
        },
        priority_formula: 'fixed:MEDIUM',
      },
      PHYSICIAN1_SESSION_TOKEN,
    );

    expect(res.statusCode).toBe(403);
  });

  it('POST /rules returns 201 for admin', async () => {
    const res = await authedPost(
      '/api/v1/intelligence/rules',
      {
        name: 'Admin rule',
        category: SuggestionCategory.MODIFIER_ADD,
        claim_type: 'AHCIP',
        conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
        suggestion_template: {
          title: 'Admin test',
          description: 'Admin test description',
          source_reference: 'SOMB',
        },
        priority_formula: 'fixed:MEDIUM',
      },
      ADMIN_SESSION_TOKEN,
    );

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.data).toBeDefined();
    expect(body.data.name).toBe('Admin rule');
    expect(body.data.isActive).toBe(false); // New rules start inactive
  });

  // --- Authentication enforcement ---
  it('returns 401 for unauthenticated requests', async () => {
    // Routes that have no body schema or where we provide a valid body
    // so that validation passes and auth is checked
    const validAnalyseBody = {
      claim_id: CLAIM_ID_1,
      claim_context: {
        claim_type: 'AHCIP',
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
        provider_specialty: 'GP',
        patient_demographics_anonymised: {},
      },
    };

    const routes: Array<{
      method: 'GET' | 'POST' | 'PUT';
      url: string;
      payload?: Record<string, unknown>;
    }> = [
      { method: 'POST', url: '/api/v1/intelligence/analyse', payload: validAnalyseBody },
      { method: 'GET', url: `/api/v1/intelligence/claims/${CLAIM_ID_1}/suggestions` },
      { method: 'POST', url: `/api/v1/intelligence/suggestions/${crypto.randomUUID()}/accept` },
      { method: 'POST', url: `/api/v1/intelligence/suggestions/${crypto.randomUUID()}/dismiss`, payload: {} },
      { method: 'GET', url: '/api/v1/intelligence/me/learning-state' },
      { method: 'GET', url: '/api/v1/intelligence/rules' },
    ];

    for (const route of routes) {
      const res = await app.inject({
        method: route.method,
        url: route.url,
        ...(route.payload !== undefined
          ? { payload: route.payload, headers: { 'content-type': 'application/json' } }
          : {}),
      });

      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.data).toBeUndefined();
    }
  });
});
