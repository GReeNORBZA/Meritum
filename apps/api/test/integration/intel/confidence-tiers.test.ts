// ============================================================================
// Domain 7: Intelligence Engine — Integration Tests: Confidence Tiers
// Tests bedside-contingent rule evaluation, pre-apply + opt-out flow,
// and digest generation in an end-to-end style.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mock shared modules (same pattern as unit tests)
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/intelligence.constants.js', () => ({
  IntelTier: { TIER_1: 'TIER_1', TIER_2: 'TIER_2', TIER_3: 'TIER_3' },
  SuggestionPriority: { HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' },
  SuggestionEventType: { GENERATED: 'GENERATED', ACCEPTED: 'ACCEPTED', DISMISSED: 'DISMISSED', SUPPRESSED: 'SUPPRESSED', UNSUPPRESSED: 'UNSUPPRESSED' },
  SuggestionCategory: {
    MODIFIER_ADD: 'MODIFIER_ADD', MODIFIER_REMOVE: 'MODIFIER_REMOVE',
    CODE_ALTERNATIVE: 'CODE_ALTERNATIVE', CODE_ADDITION: 'CODE_ADDITION',
    MISSED_BILLING: 'MISSED_BILLING', REJECTION_RISK: 'REJECTION_RISK',
    DOCUMENTATION_GAP: 'DOCUMENTATION_GAP', FEE_OPTIMISATION: 'FEE_OPTIMISATION',
    WCB_TIMING: 'WCB_TIMING', WCB_COMPLETENESS: 'WCB_COMPLETENESS',
    REVIEW_RECOMMENDED: 'REVIEW_RECOMMENDED',
  },
  SuggestionStatus: { PENDING: 'PENDING', ACCEPTED: 'ACCEPTED', DISMISSED: 'DISMISSED' },
  PRIORITY_THRESHOLD_DEFAULTS: {
    HIGH: { priority: 'HIGH', revenueImpactMin: '20.01', revenueImpactMax: null, rejectionRiskMin: 0.80, rejectionRiskMax: null, description: '' },
    MEDIUM: { priority: 'MEDIUM', revenueImpactMin: '5.00', revenueImpactMax: '20.00', rejectionRiskMin: 0.50, rejectionRiskMax: 0.80, description: '' },
    LOW: { priority: 'LOW', revenueImpactMin: '0.00', revenueImpactMax: '5.00', rejectionRiskMin: 0, rejectionRiskMax: 0.50, description: '' },
  },
  SUPPRESSION_THRESHOLD: 5,
  MIN_COHORT_SIZE: 10,
  IntelAuditAction: {
    SUGGESTION_GENERATED: 'intel.suggestion_generated',
    SUGGESTION_ACCEPTED: 'intel.suggestion_accepted',
    SUGGESTION_DISMISSED: 'intel.suggestion_dismissed',
    RULE_SUPPRESSED: 'intel.rule_suppressed',
    RULE_UNSUPPRESSED: 'intel.rule_unsuppressed',
    LLM_ESCALATION: 'intel.llm_escalation',
    PREFERENCES_UPDATED: 'intel.preferences_updated',
    CLAIM_ANALYSED: 'intel.claim_analysed',
  },
  ConfidenceTier: {
    TIER_A: 'TIER_A',
    TIER_B: 'TIER_B',
    TIER_C: 'TIER_C',
    SUPPRESS: 'SUPPRESS',
  },
}));

vi.mock('@meritum/shared/schemas/db/intelligence.schema.js', () => ({
  aiRules: {},
  aiProviderLearning: {},
  aiSpecialtyCohorts: {},
  aiSuggestionEvents: {},
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  evaluateTier1Rules,
  detectBedsideSignals,
  resolveConfidenceTier,
  processBedsideTierBRemoval,
  type ClaimContextDeps,
  type Tier1Deps,
  type ClaimContext,
  type Suggestion,
  type BedsideLearningDeps,
} from '../../../src/domains/intel/intel.service.js';
import {
  computeProviderDigest,
  generateWeeklyDigests,
  type DigestDeps,
  type DigestEventRow,
} from '../../../src/domains/intel/intel.digest.service.js';
import type { SelectAiRule } from '@meritum/shared/schemas/db/intelligence.schema.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeClaimContextDeps(overrides: {
  importSource?: string;
  dayOfWeek?: number;
  afterHoursFlag?: boolean;
} = {}): ClaimContextDeps {
  // Default to a Monday (2026-02-16) to avoid weekend signals
  // Use Sunday (2026-02-15) only when explicitly requested
  const isWeekend = overrides.dayOfWeek === 0 || overrides.dayOfWeek === 6;
  const dos = isWeekend ? '2026-02-15' : '2026-02-16'; // Sun vs Mon

  return {
    getClaim: async () => ({
      claimId: 'claim-int-1',
      claimType: 'AHCIP',
      state: 'DRAFT',
      dateOfService: dos,
      importSource: overrides.importSource ?? 'MANUAL',
      patientId: 'patient-int-1',
    }),
    getAhcipDetails: async () => ({
      healthServiceCode: '03.04A',
      modifier1: null, modifier2: null, modifier3: null,
      diagnosticCode: '401',
      functionalCentre: 'XXAA01',
      baNumber: '12345',
      encounterType: 'OFFICE',
      calls: 1, timeSpent: 15,
      facilityNumber: null,
      referralPractitioner: null,
      shadowBillingFlag: false,
      pcpcmBasketFlag: false,
      afterHoursFlag: overrides.afterHoursFlag ?? false,
      afterHoursType: null,
      submittedFee: '45.00',
    }),
    getWcbDetails: async () => null,
    getPatientDemographics: async () => ({
      dateOfBirth: '1981-02-15',
      gender: 'M',
    }),
    getProvider: async () => ({
      specialtyCode: 'GP',
      physicianType: 'GENERAL',
    }),
    getDefaultLocation: async () => ({
      functionalCentre: 'XXAA01',
      facilityNumber: null,
      rrnpEligible: false,
    }),
    getHscCode: async () => ({
      hscCode: '03.04A',
      baseFee: '45.00',
      feeType: 'FFS',
      specialtyRestrictions: [],
      facilityRestrictions: [],
      modifierEligibility: ['CMGP', 'TELE'],
      pcpcmBasket: 'not_applicable',
      maxPerDay: null,
      requiresReferral: false,
      surchargeEligible: true,
    }),
    getModifierDefinitions: async () => [],
    getDiCode: async () => ({
      diCode: '401',
      qualifiesSurcharge: false,
      qualifiesBcp: false,
    }),
    getReferenceSet: async () => [],
    getCrossClaimCount: async () => 0,
    getCrossClaimSum: async () => 0,
    getCrossClaimExists: async () => false,
  };
}

function makeBedsideRule(ruleId: string): Record<string, any> {
  return {
    ruleId,
    name: 'Test Bedside Rule',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'field_compare',
      field: 'claim.claimType',
      operator: '==',
      value: 'AHCIP',
    },
    suggestionTemplate: {
      title: 'Add after-hours modifier',
      description: 'After-hours modifier applies to this encounter.',
      source_reference: 'SOMB 2026 — After Hours Premium',
      revenue_impact_formula: 'fixed:25.00',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'AFTE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    isActive: true,
    isBedsideContingent: true,
    sombVersion: '2026.1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function makeTier1Deps(rules: Record<string, any>[], learningStates: Record<string, any>[] = []) {
  const events: any[] = [];
  const autoApplied: string[] = [];
  const preApplied: string[] = [];
  const shownIncrements: string[] = [];

  const deps: Tier1Deps = {
    getActiveRulesForClaim: async () => rules as unknown as SelectAiRule[],
    getProviderLearningForRules: async (_pid: string, ruleIds: string[]) =>
      learningStates.filter((ls: any) => ruleIds.includes(ls.ruleId)) as any[],
    incrementShown: async (_pid: string, ruleId: string) => {
      shownIncrements.push(ruleId);
      return {} as any;
    },
    appendSuggestionEvent: async (event: any) => {
      events.push(event);
      return {} as any;
    },
    recordAutoApplied: async (_pid: string, ruleId: string) => {
      autoApplied.push(ruleId);
    },
    recordPreApplied: async (_pid: string, ruleId: string) => {
      preApplied.push(ruleId);
    },
  };

  return { deps, events, autoApplied, preApplied, shownIncrements };
}

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration — Confidence Tier Rule Evaluation with Connect Care Import', () => {
  const providerId = 'provider-integ';
  const claimId = 'claim-integ';

  it('Connect Care CSV import triggers TIER_A auto-apply for bedside rule', async () => {
    const rule = makeBedsideRule('bedside-cc-1');
    const contextDeps = makeClaimContextDeps({ importSource: 'CONNECT_CARE_CSV' });
    const { deps, autoApplied, shownIncrements } = makeTier1Deps([rule]);

    const suggestions = await evaluateTier1Rules(claimId, providerId, contextDeps, deps);

    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].confidenceTier).toBe('TIER_A');
    expect(suggestions[0].autoApplied).toBe(true);
    expect(suggestions[0].suggestedChanges).toEqual([
      { field: 'ahcip.modifier1', valueFormula: 'AFTE' },
    ]);
    expect(autoApplied).toContain('bedside-cc-1');
    expect(shownIncrements).not.toContain('bedside-cc-1');
  });

  it('SFTP import also triggers TIER_A', async () => {
    const rule = makeBedsideRule('bedside-sftp-1');
    const contextDeps = makeClaimContextDeps({ importSource: 'CONNECT_CARE_SFTP' });
    const { deps, autoApplied } = makeTier1Deps([rule]);

    const suggestions = await evaluateTier1Rules(claimId, providerId, contextDeps, deps);

    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].confidenceTier).toBe('TIER_A');
    expect(autoApplied).toContain('bedside-sftp-1');
  });

  it('non-bedside rules are unaffected by import source', async () => {
    const normalRule = {
      ...makeBedsideRule('normal-rule'),
      isBedsideContingent: false,
    };
    const contextDeps = makeClaimContextDeps({ importSource: 'CONNECT_CARE_CSV' });
    const { deps, autoApplied } = makeTier1Deps([normalRule]);

    const suggestions = await evaluateTier1Rules(claimId, providerId, contextDeps, deps);

    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].confidenceTier).toBeUndefined();
    expect(suggestions[0].autoApplied).toBeUndefined();
    expect(autoApplied).toHaveLength(0);
  });
});

describe('Integration — Pre-apply + Opt-out Flow', () => {
  it('TIER_B pre-apply → user keeps → acceptance increments (simulated)', async () => {
    const ruleId = 'bedside-preapply';
    const providerId = 'prov-preapply';
    const rule = makeBedsideRule(ruleId);

    // Provider has high acceptance rate (80%) → TIER_B
    const learning = {
      learningId: 'learn-1',
      providerId,
      ruleId,
      timesShown: 10,
      timesAccepted: 8,
      timesDismissed: 2,
      consecutiveDismissals: 0,
      autoAppliedCount: 0,
      preAppliedCount: 5,
      preAppliedRemovedCount: 1,
      isSuppressed: false,
      priorityAdjustment: 0,
      lastShownAt: null,
      lastFeedbackAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Weekday MANUAL import = no Tier A signals
    const contextDeps = makeClaimContextDeps({ importSource: 'MANUAL', dayOfWeek: 2 });
    const { deps, preApplied, shownIncrements } = makeTier1Deps([rule], [learning]);

    const suggestions = await evaluateTier1Rules('claim-pa', providerId, contextDeps, deps);

    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].confidenceTier).toBe('TIER_B');
    expect(suggestions[0].preApplied).toBe(true);
    expect(preApplied).toContain(ruleId);
    // TIER_B does increment times_shown
    expect(shownIncrements).toContain(ruleId);
  });

  it('TIER_B pre-apply → user removes → demotion check', async () => {
    // Simulate: 12 pre-applies, 7 removals → removal rate = 58% > 50% → demote

    let priorityAdjusted = false;
    let adjustmentValue: number | null = null;

    const deps: BedsideLearningDeps = {
      getLearningState: async () => ({
        preAppliedCount: 12,
        preAppliedRemovedCount: 7,
        timesShown: 20,
        timesAccepted: 10,
        timesDismissed: 10,
        isSuppressed: false,
        priorityAdjustment: 0,
      } as any),
      updatePriorityAdjustment: async (_pid, _rid, adj) => {
        priorityAdjusted = true;
        adjustmentValue = adj;
        return {} as any;
      },
      recordPreAppliedRemoval: async () => ({
        preAppliedCount: 12,
        preAppliedRemovedCount: 7,
      } as any),
      recordDismissal: async () => ({} as any),
    };

    const result = await processBedsideTierBRemoval('prov-1', 'rule-1', deps);

    expect(result.demotedToC).toBe(true);
    expect(priorityAdjusted).toBe(true);
    expect(adjustmentValue).toBe(-1);
  });

  it('TIER_B pre-apply → user removes → no demotion if under threshold', async () => {
    const deps: BedsideLearningDeps = {
      getLearningState: async () => ({
        preAppliedCount: 10,
        preAppliedRemovedCount: 4,
      } as any),
      updatePriorityAdjustment: async () => ({} as any),
      recordPreAppliedRemoval: async () => ({
        preAppliedCount: 10,
        preAppliedRemovedCount: 4,
      } as any),
      recordDismissal: async () => ({} as any),
    };

    const result = await processBedsideTierBRemoval('prov-1', 'rule-1', deps);
    expect(result.demotedToC).toBe(false);
  });
});

describe('Integration — Digest Generation', () => {
  it('end-to-end: generates digest and emits notification', async () => {
    const notifications: any[] = [];
    const auditEntries: any[] = [];

    const deps: DigestDeps = {
      getActiveProviderIds: async () => ['prov-active'],
      getSuggestionEventsForPeriod: async () => [
        {
          eventId: '1', claimId: 'c1', suggestionId: 's1', ruleId: 'r1',
          providerId: 'prov-active', eventType: 'GENERATED', tier: 1,
          category: 'MODIFIER_ADD', revenueImpact: null, createdAt: new Date(),
        },
        {
          eventId: '2', claimId: 'c2', suggestionId: 's2', ruleId: 'r2',
          providerId: 'prov-active', eventType: 'GENERATED', tier: 1,
          category: 'REJECTION_RISK', revenueImpact: null, createdAt: new Date(),
        },
        {
          eventId: '3', claimId: 'c1', suggestionId: 's1', ruleId: 'r1',
          providerId: 'prov-active', eventType: 'ACCEPTED', tier: 1,
          category: 'MODIFIER_ADD', revenueImpact: '25.00', createdAt: new Date(),
        },
        {
          eventId: '4', claimId: 'c2', suggestionId: 's2', ruleId: 'r2',
          providerId: 'prov-active', eventType: 'DISMISSED', tier: 1,
          category: 'REJECTION_RISK', revenueImpact: null, createdAt: new Date(),
        },
      ],
      emitNotification: async (event) => {
        notifications.push(event);
      },
      auditLog: async (entry) => {
        auditEntries.push(entry);
      },
    };

    const start = new Date('2026-02-01');
    const end = new Date('2026-02-08');
    const digests = await generateWeeklyDigests(deps, start, end);

    // One active provider with events
    expect(digests).toHaveLength(1);
    const digest = digests[0];

    // Verify aggregate counts
    expect(digest.totalGenerated).toBe(2);
    expect(digest.totalAccepted).toBe(1);
    expect(digest.totalDismissed).toBe(1);
    expect(digest.estimatedRevenueImpact).toBe(25.00);
    expect(digest.acceptanceRate).toBe(0.5);

    // Verify category breakdown
    expect(digest.topCategories).toHaveLength(2);
    const modAdd = digest.topCategories.find(c => c.category === 'MODIFIER_ADD');
    expect(modAdd).toBeDefined();
    expect(modAdd!.generated).toBe(1);
    expect(modAdd!.accepted).toBe(1);
    expect(modAdd!.revenueImpact).toBe(25.00);

    // Verify notification emitted
    expect(notifications).toHaveLength(1);
    expect(notifications[0].type).toBe('INTEL_WEEKLY_DIGEST');
    expect(notifications[0].providerId).toBe('prov-active');
    expect(notifications[0].payload.totalGenerated).toBe(2);
    expect(notifications[0].payload.estimatedRevenueImpact).toBe(25.00);

    // Verify audit logged
    expect(auditEntries).toHaveLength(1);
    expect(auditEntries[0].action).toBe('intel.claim_analysed');
    expect(auditEntries[0].details.digestType).toBe('weekly');
  });
});
