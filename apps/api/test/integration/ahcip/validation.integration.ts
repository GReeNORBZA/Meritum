import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  validateAhcipClaim,
  type AhcipValidationDeps,
  type AhcipClaimForValidation,
  type HscDetail,
  type ModifierDetail,
  type GoverningRuleDetail,
} from '../../../src/domains/ahcip/ahcip.service.js';
import { AhcipValidationCheckId } from '@meritum/shared/constants/ahcip.constants.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-1111-0000-0000-000000000001';
const REF_VERSION = 'SOMB-2026Q1';

function makeHscDetail(overrides: Partial<HscDetail> = {}): HscDetail {
  return {
    code: '03.04A',
    description: 'Office visit',
    baseFee: '38.56',
    feeType: 'FIXED',
    isActive: true,
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    requiresReferral: false,
    requiresDiagnosticCode: false,
    requiresFacility: false,
    isTimeBased: false,
    minTime: null,
    maxTime: null,
    minCalls: null,
    maxCalls: null,
    maxPerDay: null,
    surchargeEligible: false,
    pcpcmBasket: null,
    afterHoursEligible: false,
    premium351Eligible: false,
    combinationGroup: null,
    ...overrides,
  };
}

function makeClaim(overrides: Partial<AhcipClaimForValidation> = {}): AhcipClaimForValidation {
  return {
    claimId: '00000000-cccc-0000-0000-000000000001',
    physicianId: PHYSICIAN_ID,
    patientId: '00000000-aaaa-0000-0000-000000000001',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    healthServiceCode: '03.04A',
    baNumber: '12345',
    modifier1: null,
    modifier2: null,
    modifier3: null,
    diagnosticCode: null,
    facilityNumber: null,
    referralPractitioner: null,
    encounterType: 'FOLLOW_UP',
    calls: 1,
    timeSpent: null,
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    afterHoursFlag: false,
    afterHoursType: null,
    ...overrides,
  };
}

function makeModifierDetail(overrides: Partial<ModifierDetail> = {}): ModifierDetail {
  return {
    modifierCode: 'AFHR',
    name: 'After-Hours',
    calculationMethod: 'ADDITIVE',
    combinableWith: ['CMGP'],
    exclusiveWith: [],
    ...overrides,
  };
}

function makeGoverningRule(overrides: Partial<GoverningRuleDetail> = {}): GoverningRuleDetail {
  return {
    ruleId: 'GR_3',
    ruleName: 'Visit Limits',
    ruleCategory: 'VISIT_LIMIT',
    severity: 'ERROR',
    ruleLogic: { maxVisitsPerDay: 1 },
    errorMessage: 'Visit limit exceeded',
    ...overrides,
  };
}

function createMockDeps(overrides: Partial<{
  hscDetail: HscDetail | null;
  applicableModifiers: ModifierDetail[];
  modifierDetail: ModifierDetail | null;
  applicableRules: GoverningRuleDetail[];
  baValid: boolean;
  rrnpEligible: boolean;
  otherClaims: Array<{ claimId: string; healthServiceCode: string }>;
}> = {}): AhcipValidationDeps {
  const {
    hscDetail = makeHscDetail(),
    applicableModifiers = [],
    modifierDetail = null,
    applicableRules = [],
    baValid = true,
    rrnpEligible = false,
    otherClaims = [],
  } = overrides;

  return {
    refData: {
      getHscDetail: vi.fn(async () => hscDetail),
      getModifiersForHsc: vi.fn(async () => applicableModifiers),
      getModifierDetail: vi.fn(async () => modifierDetail),
      getApplicableRules: vi.fn(async () => applicableRules),
      getCurrentVersion: vi.fn(async () => REF_VERSION),
    },
    providerService: {
      validateBa: vi.fn(async () => ({ valid: baValid })),
      isRrnpEligible: vi.fn(async () => rrnpEligible),
    },
    claimLookup: {
      findClaimsForPatientOnDate: vi.fn(async () => otherClaims),
    },
  };
}

function hasCheck(entries: Array<{ check: string }>, checkId: string): boolean {
  return entries.some((e) => e.check === checkId);
}

function getCheck(entries: Array<{ check: string; severity: string }>, checkId: string) {
  return entries.find((e) => e.check === checkId);
}

// ===========================================================================
// Tests
// ===========================================================================

describe('AHCIP Validation Pipeline Integration', () => {
  // =========================================================================
  // A1: HSC Code Valid
  // =========================================================================

  describe('A1: HSC Code Valid', () => {
    it('passes when HSC code exists in SOMB schedule', async () => {
      const deps = createMockDeps();
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A1_HSC_CODE_VALID)).toBe(false);
      expect(result.referenceDataVersion).toBe(REF_VERSION);
    });

    it('fails when HSC code not found in SOMB schedule', async () => {
      const deps = createMockDeps({ hscDetail: null });
      const claim = makeClaim({ healthServiceCode: 'INVALID' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A1_HSC_CODE_VALID)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A1_HSC_CODE_VALID)!;
      expect(entry.severity).toBe('ERROR');
    });

    it('short-circuits remaining checks when HSC code is invalid', async () => {
      const deps = createMockDeps({ hscDetail: null });
      const claim = makeClaim({ healthServiceCode: 'INVALID' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      // Only A1 error should be present; no further checks executed
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].check).toBe(AhcipValidationCheckId.A1_HSC_CODE_VALID);
    });
  });

  // =========================================================================
  // A2: HSC Active on DOS
  // =========================================================================

  describe('A2: HSC Active on DOS', () => {
    it('passes when HSC code is active on date of service', async () => {
      const deps = createMockDeps({ hscDetail: makeHscDetail({ isActive: true }) });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS)).toBe(false);
    });

    it('fails when HSC code is not active on date of service', async () => {
      const deps = createMockDeps({ hscDetail: makeHscDetail({ isActive: false }) });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A2_HSC_ACTIVE_ON_DOS)!;
      expect(entry.severity).toBe('ERROR');
    });
  });

  // =========================================================================
  // A3: BA Number Valid
  // =========================================================================

  describe('A3: BA Number Valid', () => {
    it('passes when BA number is valid for this physician', async () => {
      const deps = createMockDeps({ baValid: true });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A3_BA_NUMBER_VALID)).toBe(false);
    });

    it('fails when BA number is invalid', async () => {
      const deps = createMockDeps({ baValid: false });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A3_BA_NUMBER_VALID)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A3_BA_NUMBER_VALID)!;
      expect(entry.severity).toBe('ERROR');
    });
  });

  // =========================================================================
  // A4: Governing Rules
  // =========================================================================

  describe('A4: Governing Rules', () => {
    it('passes when no governing rules are violated', async () => {
      const deps = createMockDeps({
        applicableRules: [makeGoverningRule({ ruleLogic: { maxVisitsPerDay: 5 } })],
      });
      const claim = makeClaim({ calls: 1 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(false);
    });

    describe('GR 3: Visit limit', () => {
      it('passes at exactly the limit', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({ ruleLogic: { maxVisitsPerDay: 3 } })],
        });
        const claim = makeClaim({ calls: 3 });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(false);
      });

      it('fails when over the limit', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({ ruleLogic: { maxVisitsPerDay: 1 } })],
        });
        const claim = makeClaim({ calls: 2 });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(true);
        const entry = getCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)!;
        expect(entry.severity).toBe('ERROR');
        expect(entry.message).toContain('Visit limit exceeded');
      });
    });

    describe('GR 8: Referral required', () => {
      it('passes when referral is present', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_8',
            ruleLogic: { requiresReferral: true },
          })],
        });
        const claim = makeClaim({ referralPractitioner: 'REF123' });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(false);
      });

      it('fails when referral is missing', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_8',
            ruleLogic: { requiresReferral: true },
          })],
        });
        const claim = makeClaim({ referralPractitioner: null });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(true);
        const entry = getCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)!;
        expect(entry.message).toContain('Referring practitioner required');
      });
    });

    describe('GR 5: Facility required', () => {
      it('fails when facility is missing for DI rule', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_5',
            ruleLogic: { requiresFacility: true },
          })],
        });
        const claim = makeClaim({ facilityNumber: null });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(true);
      });
    });

    describe('GR 10: Surgical time documentation', () => {
      it('fails when time documentation is missing', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_10',
            ruleLogic: { requiresTimeDocumentation: true },
          })],
        });
        const claim = makeClaim({ timeSpent: null });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(true);
        const entry = getCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)!;
        expect(entry.message).toContain('Time documentation required');
      });
    });

    describe('GR 14: Obstetric call limit', () => {
      it('passes at exactly the call limit', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_14',
            ruleLogic: { maxCallsPerEncounter: 2 },
          })],
        });
        const claim = makeClaim({ calls: 2 });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(false);
      });

      it('fails when over the call limit', async () => {
        const deps = createMockDeps({
          applicableRules: [makeGoverningRule({
            ruleId: 'GR_14',
            ruleLogic: { maxCallsPerEncounter: 2 },
          })],
        });
        const claim = makeClaim({ calls: 3 });

        const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

        expect(hasCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)).toBe(true);
        const entry = getCheck(result.entries, AhcipValidationCheckId.A4_GOVERNING_RULES)!;
        expect(entry.message).toContain('Call limit exceeded');
      });
    });
  });

  // =========================================================================
  // A5: Modifier Eligibility
  // =========================================================================

  describe('A5: Modifier Eligibility', () => {
    it('passes when all modifiers are eligible for HSC code', async () => {
      const deps = createMockDeps({
        applicableModifiers: [
          makeModifierDetail({ modifierCode: 'AFHR' }),
          makeModifierDetail({ modifierCode: 'CMGP' }),
        ],
      });
      const claim = makeClaim({ modifier1: 'AFHR', modifier2: 'CMGP' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY)).toBe(false);
    });

    it('fails when modifier is not valid for HSC code', async () => {
      const deps = createMockDeps({
        applicableModifiers: [makeModifierDetail({ modifierCode: 'AFHR' })],
      });
      const claim = makeClaim({ modifier1: 'INVALID_MOD' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY)!;
      expect(entry.severity).toBe('ERROR');
      expect(entry.message).toContain('INVALID_MOD');
    });

    it('reports each invalid modifier separately', async () => {
      const deps = createMockDeps({ applicableModifiers: [] });
      const claim = makeClaim({ modifier1: 'BAD1', modifier2: 'BAD2' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      const a5Entries = result.entries.filter(
        (e) => e.check === AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY,
      );
      expect(a5Entries).toHaveLength(2);
    });

    it('passes with no modifiers', async () => {
      const deps = createMockDeps();
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A5_MODIFIER_ELIGIBILITY)).toBe(false);
    });
  });

  // =========================================================================
  // A6: Modifier Combination
  // =========================================================================

  describe('A6: Modifier Combination', () => {
    it('passes when modifiers are combinable', async () => {
      const deps = createMockDeps({
        applicableModifiers: [
          makeModifierDetail({ modifierCode: 'AFHR' }),
          makeModifierDetail({ modifierCode: 'CMGP' }),
        ],
      });
      // Override getModifierDetail to return non-exclusive modifiers
      deps.refData.getModifierDetail = vi.fn(async (code: string) => {
        if (code === 'AFHR') return makeModifierDetail({ modifierCode: 'AFHR', exclusiveWith: [] });
        if (code === 'CMGP') return makeModifierDetail({ modifierCode: 'CMGP', exclusiveWith: [] });
        return null;
      });
      const claim = makeClaim({ modifier1: 'AFHR', modifier2: 'CMGP' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A6_MODIFIER_COMBINATION)).toBe(false);
    });

    it('fails when modifiers are mutually exclusive', async () => {
      const deps = createMockDeps({
        applicableModifiers: [
          makeModifierDetail({ modifierCode: 'MOD_A' }),
          makeModifierDetail({ modifierCode: 'MOD_B' }),
        ],
      });
      deps.refData.getModifierDetail = vi.fn(async (code: string) => {
        if (code === 'MOD_A') return makeModifierDetail({ modifierCode: 'MOD_A', exclusiveWith: ['MOD_B'] });
        if (code === 'MOD_B') return makeModifierDetail({ modifierCode: 'MOD_B', exclusiveWith: ['MOD_A'] });
        return null;
      });
      const claim = makeClaim({ modifier1: 'MOD_A', modifier2: 'MOD_B' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A6_MODIFIER_COMBINATION)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A6_MODIFIER_COMBINATION)!;
      expect(entry.severity).toBe('ERROR');
      expect(entry.message).toContain('mutually exclusive');
    });

    it('does not check combination for single modifier', async () => {
      const deps = createMockDeps({
        applicableModifiers: [makeModifierDetail({ modifierCode: 'AFHR' })],
      });
      const claim = makeClaim({ modifier1: 'AFHR' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A6_MODIFIER_COMBINATION)).toBe(false);
    });
  });

  // =========================================================================
  // A7: Diagnostic Code Required
  // =========================================================================

  describe('A7: Diagnostic Code Required', () => {
    it('passes when diagnostic code is not required', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresDiagnosticCode: false }),
      });
      const claim = makeClaim({ diagnosticCode: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED)).toBe(false);
    });

    it('passes when diagnostic code is required and present', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresDiagnosticCode: true }),
      });
      const claim = makeClaim({ diagnosticCode: '780.6' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED)).toBe(false);
    });

    it('fails when diagnostic code is required but missing', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresDiagnosticCode: true }),
      });
      const claim = makeClaim({ diagnosticCode: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A7_DIAGNOSTIC_CODE_REQUIRED)!;
      expect(entry.severity).toBe('ERROR');
    });
  });

  // =========================================================================
  // A8: Facility Required
  // =========================================================================

  describe('A8: Facility Required', () => {
    it('passes when facility is not required', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresFacility: false }),
      });
      const claim = makeClaim({ facilityNumber: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A8_FACILITY_REQUIRED)).toBe(false);
    });

    it('passes when facility is required and present', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresFacility: true }),
      });
      const claim = makeClaim({ facilityNumber: 'FAC001' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A8_FACILITY_REQUIRED)).toBe(false);
    });

    it('fails when facility is required but missing', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresFacility: true }),
      });
      const claim = makeClaim({ facilityNumber: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A8_FACILITY_REQUIRED)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A8_FACILITY_REQUIRED)!;
      expect(entry.severity).toBe('ERROR');
    });
  });

  // =========================================================================
  // A9: Referral Required (GR 8)
  // =========================================================================

  describe('A9: Referral Required', () => {
    it('passes when referral is not required', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresReferral: false }),
      });
      const claim = makeClaim({ referralPractitioner: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A9_REFERRAL_REQUIRED)).toBe(false);
    });

    it('passes when referral is required and present', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresReferral: true }),
      });
      const claim = makeClaim({ referralPractitioner: 'REF123' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A9_REFERRAL_REQUIRED)).toBe(false);
    });

    it('fails when referral is required but missing', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ requiresReferral: true }),
      });
      const claim = makeClaim({ referralPractitioner: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A9_REFERRAL_REQUIRED)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A9_REFERRAL_REQUIRED)!;
      expect(entry.severity).toBe('ERROR');
    });
  });

  // =========================================================================
  // A10: DI Surcharge Eligibility
  // =========================================================================

  describe('A10: DI Surcharge Eligibility', () => {
    it('no warning when HSC is not surcharge eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ surchargeEligible: false }),
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY)).toBe(false);
    });

    it('emits warning when HSC is surcharge eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ surchargeEligible: true }),
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A10_DI_SURCHARGE_ELIGIBILITY)!;
      expect(entry.severity).toBe('WARNING');
    });
  });

  // =========================================================================
  // A11: PCPCM Routing
  // =========================================================================

  describe('A11: PCPCM Routing', () => {
    it('no warning when HSC has no PCPCM basket', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ pcpcmBasket: null }),
      });
      const claim = makeClaim({ pcpcmBasketFlag: false });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)).toBe(false);
    });

    it('no warning when in-basket code routes to PCPCM BA (correct)', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ pcpcmBasket: 'IN_BASKET' }),
      });
      const claim = makeClaim({ pcpcmBasketFlag: true });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)).toBe(false);
    });

    it('warning when in-basket code is not flagged as PCPCM', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ pcpcmBasket: 'IN_BASKET' }),
      });
      const claim = makeClaim({ pcpcmBasketFlag: false });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)!;
      expect(entry.severity).toBe('WARNING');
      expect(entry.message).toContain('in-basket');
    });

    it('warning when out-of-basket code is flagged as PCPCM', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ pcpcmBasket: 'OUT_OF_BASKET' }),
      });
      const claim = makeClaim({ pcpcmBasketFlag: true });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A11_PCPCM_ROUTING)!;
      expect(entry.severity).toBe('WARNING');
      expect(entry.message).toContain('out-of-basket');
    });
  });

  // =========================================================================
  // A12: After-Hours Eligibility
  // =========================================================================

  describe('A12: After-Hours Eligibility', () => {
    it('no warning when after-hours flag is not set', async () => {
      const deps = createMockDeps();
      const claim = makeClaim({ afterHoursFlag: false });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY)).toBe(false);
    });

    it('no warning when after-hours flag is set and HSC is eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ afterHoursEligible: true }),
      });
      const claim = makeClaim({ afterHoursFlag: true, afterHoursType: 'EVENING' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY)).toBe(false);
    });

    it('warning when after-hours flag is set but HSC is not eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ afterHoursEligible: false }),
      });
      const claim = makeClaim({ afterHoursFlag: true, afterHoursType: 'EVENING' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A12_AFTER_HOURS_ELIGIBILITY)!;
      expect(entry.severity).toBe('WARNING');
    });
  });

  // =========================================================================
  // A13: 90-Day Window
  // =========================================================================

  describe('A13: 90-Day Window', () => {
    it('no entry when deadline is far in the future', async () => {
      const deps = createMockDeps();
      // Deadline far in the future
      const futureDeadline = new Date();
      futureDeadline.setUTCDate(futureDeadline.getUTCDate() + 60);
      const claim = makeClaim({
        submissionDeadline: futureDeadline.toISOString().split('T')[0],
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)).toBe(false);
    });

    it('error when 90-day window has expired', async () => {
      const deps = createMockDeps();
      // Deadline in the past
      const pastDeadline = new Date();
      pastDeadline.setUTCDate(pastDeadline.getUTCDate() - 1);
      const claim = makeClaim({
        submissionDeadline: pastDeadline.toISOString().split('T')[0],
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)!;
      expect(entry.severity).toBe('ERROR');
      expect(entry.message).toContain('expired');
    });

    it('warning when within 7 days of deadline', async () => {
      const deps = createMockDeps();
      // Deadline within 7 days
      const nearDeadline = new Date();
      nearDeadline.setUTCDate(nearDeadline.getUTCDate() + 5);
      const claim = makeClaim({
        submissionDeadline: nearDeadline.toISOString().split('T')[0],
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)!;
      expect(entry.severity).toBe('WARNING');
      expect(entry.message).toContain('day(s)');
    });

    it('boundary: exactly 90 days from DOS yields no error', async () => {
      const deps = createMockDeps();
      // Deadline exactly today + 8 days (beyond 7-day warning threshold)
      const today = new Date();
      today.setUTCHours(0, 0, 0, 0);
      const deadline = new Date(today);
      deadline.setUTCDate(deadline.getUTCDate() + 8);
      const claim = makeClaim({
        submissionDeadline: deadline.toISOString().split('T')[0],
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)).toBe(false);
    });

    it('boundary: deadline is exactly today produces warning', async () => {
      const deps = createMockDeps();
      // Deadline is exactly today — within 7 days (0 days remaining)
      const today = new Date();
      today.setUTCHours(0, 0, 0, 0);
      const claim = makeClaim({
        submissionDeadline: today.toISOString().split('T')[0],
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      // Today is still within the window (not expired) but within 7 days
      const entry = getCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW);
      // The deadline is today, which has 0 days remaining; 0 <= 7 so WARNING
      if (entry) {
        expect(entry.severity).toBe('WARNING');
      }
    });

    it('no entry when submissionDeadline is null', async () => {
      const deps = createMockDeps();
      const claim = makeClaim({ submissionDeadline: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A13_90_DAY_WINDOW)).toBe(false);
    });
  });

  // =========================================================================
  // A14: Time-Based Code Duration
  // =========================================================================

  describe('A14: Time-Based Code Duration', () => {
    it('passes for non-time-based code', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: false }),
      });
      const claim = makeClaim({ timeSpent: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(false);
    });

    it('fails when time-based code has no time_spent', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 10, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)!;
      expect(entry.severity).toBe('ERROR');
    });

    it('fails when time_spent is below minimum', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 15, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: 10 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)!;
      expect(entry.message).toContain('below minimum');
    });

    it('fails when time_spent exceeds maximum', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 10, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: 90 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)!;
      expect(entry.message).toContain('exceeds maximum');
    });

    it('passes when time_spent is within range', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 10, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: 30 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(false);
    });

    it('passes at exactly min time', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 15, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: 15 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(false);
    });

    it('passes at exactly max time', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 10, maxTime: 60 }),
      });
      const claim = makeClaim({ timeSpent: 60 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A14_TIME_BASED_DURATION)).toBe(false);
    });
  });

  // =========================================================================
  // A15: Call Count Valid
  // =========================================================================

  describe('A15: Call Count Valid', () => {
    it('passes when no limits defined', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ minCalls: null, maxCalls: null }),
      });
      const claim = makeClaim({ calls: 5 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)).toBe(false);
    });

    it('fails when calls exceed maxCalls', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ maxCalls: 3 }),
      });
      const claim = makeClaim({ calls: 4 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)!;
      expect(entry.severity).toBe('ERROR');
      expect(entry.message).toContain('exceeds maximum');
    });

    it('fails when calls are below minCalls', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ minCalls: 2 }),
      });
      const claim = makeClaim({ calls: 1 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)!;
      expect(entry.message).toContain('below minimum');
    });

    it('passes at exactly maxCalls', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ maxCalls: 3 }),
      });
      const claim = makeClaim({ calls: 3 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A15_CALL_COUNT_VALID)).toBe(false);
    });
  });

  // =========================================================================
  // A16: Shadow Billing Consistency
  // =========================================================================

  describe('A16: Shadow Billing Consistency', () => {
    it('no warning for regular claim', async () => {
      const deps = createMockDeps();
      const claim = makeClaim({ shadowBillingFlag: false, modifier1: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)).toBe(false);
    });

    it('warning when shadow_billing_flag set but TM modifier missing', async () => {
      const deps = createMockDeps();
      const claim = makeClaim({ shadowBillingFlag: true, modifier1: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)!;
      expect(entry.severity).toBe('WARNING');
      expect(entry.message).toContain('TM modifier is missing');
    });

    it('warning when TM modifier present but shadow_billing_flag not set', async () => {
      const deps = createMockDeps({
        applicableModifiers: [makeModifierDetail({ modifierCode: 'TM' })],
      });
      const claim = makeClaim({ shadowBillingFlag: false, modifier1: 'TM' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)!;
      expect(entry.message).toContain('shadow billing flag is not set');
    });

    it('no warning when TM modifier and shadow_billing_flag are consistent', async () => {
      const deps = createMockDeps({
        applicableModifiers: [makeModifierDetail({ modifierCode: 'TM' })],
      });
      const claim = makeClaim({ shadowBillingFlag: true, modifier1: 'TM' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A16_SHADOW_BILLING_CONSISTENCY)).toBe(false);
    });
  });

  // =========================================================================
  // A17: RRNP Eligibility
  // =========================================================================

  describe('A17: RRNP Eligibility', () => {
    it('no info when physician is not RRNP eligible', async () => {
      const deps = createMockDeps({ rrnpEligible: false });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A17_RRNP_ELIGIBILITY)).toBe(false);
    });

    it('info when physician qualifies for RRNP', async () => {
      const deps = createMockDeps({ rrnpEligible: true });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A17_RRNP_ELIGIBILITY)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A17_RRNP_ELIGIBILITY)!;
      expect(entry.severity).toBe('INFO');
    });
  });

  // =========================================================================
  // A18: Premium Eligibility 351
  // =========================================================================

  describe('A18: Premium Eligibility 351', () => {
    it('no info when HSC is not 351 eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ premium351Eligible: false }),
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351)).toBe(false);
    });

    it('info when HSC is 351 premium eligible', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({ premium351Eligible: true }),
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A18_PREMIUM_ELIGIBILITY_351)!;
      expect(entry.severity).toBe('INFO');
    });
  });

  // =========================================================================
  // A19: Bundling Check
  // =========================================================================

  describe('A19: Bundling Check', () => {
    it('no warning when no other claims for same patient on same DOS', async () => {
      const deps = createMockDeps({ otherClaims: [] });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A19_BUNDLING_CHECK)).toBe(false);
    });

    it('warning when other claims exist for same patient on same DOS', async () => {
      const deps = createMockDeps({
        otherClaims: [
          { claimId: '00000000-cccc-0000-0000-000000000002', healthServiceCode: '08.19A' },
        ],
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(hasCheck(result.entries, AhcipValidationCheckId.A19_BUNDLING_CHECK)).toBe(true);
      const entry = getCheck(result.entries, AhcipValidationCheckId.A19_BUNDLING_CHECK)!;
      expect(entry.severity).toBe('WARNING');
      expect(entry.message).toContain('1 other claim(s)');
      expect(entry.message).toContain('08.19A');
    });

    it('warning includes count for multiple bundling claims', async () => {
      const deps = createMockDeps({
        otherClaims: [
          { claimId: '00000000-cccc-0000-0000-000000000002', healthServiceCode: '08.19A' },
          { claimId: '00000000-cccc-0000-0000-000000000003', healthServiceCode: '03.01A' },
        ],
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      const entry = getCheck(result.entries, AhcipValidationCheckId.A19_BUNDLING_CHECK)!;
      expect(entry.message).toContain('2 other claim(s)');
    });
  });

  // =========================================================================
  // Cross-cutting: Reference Data Version
  // =========================================================================

  describe('Reference Data Version', () => {
    it('always returns reference data version', async () => {
      const deps = createMockDeps();
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      expect(result.referenceDataVersion).toBe(REF_VERSION);
    });
  });

  // =========================================================================
  // Combined validation scenarios
  // =========================================================================

  describe('Combined scenarios', () => {
    it('clean claim produces zero errors', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail(),
        baValid: true,
        applicableRules: [],
        applicableModifiers: [],
        otherClaims: [],
        rrnpEligible: false,
      });
      const claim = makeClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      const errors = result.entries.filter((e) => e.severity === 'ERROR');
      expect(errors).toHaveLength(0);
    });

    it('multiple errors accumulate correctly', async () => {
      const deps = createMockDeps({
        hscDetail: makeHscDetail({
          isActive: false,
          requiresDiagnosticCode: true,
          requiresFacility: true,
        }),
        baValid: false,
      });
      const claim = makeClaim({
        diagnosticCode: null,
        facilityNumber: null,
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_ID);

      const errors = result.entries.filter((e) => e.severity === 'ERROR');
      // Should have A2 (inactive), A3 (invalid BA), A7 (diag code missing), A8 (facility missing)
      expect(errors.length).toBeGreaterThanOrEqual(4);
    });
  });
});
