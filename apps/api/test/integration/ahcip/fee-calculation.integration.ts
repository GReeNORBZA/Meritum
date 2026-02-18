import { describe, it, expect, vi } from 'vitest';
import {
  calculateFeePreview,
  getFeeBreakdown,
  type FeeCalculationDeps,
  type FeeCalculateInput,
  type HscDetail,
  type ModifierFeeImpact,
} from '../../../src/domains/ahcip/ahcip.service.js';
import { SHADOW_BILLING_FEE } from '@meritum/shared/constants/ahcip.constants.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-1111-0000-0000-000000000001';
const CLAIM_ID = '00000000-cccc-0000-0000-000000000001';

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
    afterHoursEligible: true,
    premium351Eligible: false,
    combinationGroup: null,
    ...overrides,
  };
}

function makeInput(overrides: Partial<FeeCalculateInput> = {}): FeeCalculateInput {
  return {
    healthServiceCode: '03.04A',
    dateOfService: '2026-01-15',
    modifier1: null,
    modifier2: null,
    modifier3: null,
    calls: 1,
    afterHoursFlag: false,
    afterHoursType: null,
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    ...overrides,
  };
}

function createMockFeeCalcDeps(overrides: {
  hscDetail?: HscDetail | null;
  modifierFeeImpact?: ModifierFeeImpact | null;
  afterHoursPremium?: string | null;
  cmgpPremium?: string | null;
  rrnpPremium?: string | null;
  edSurcharge?: string | null;
  rrnpEligible?: boolean;
  modifierImpactFn?: (mod: string, hsc: string, dos: string) => Promise<ModifierFeeImpact | null>;
} = {}): FeeCalculationDeps {
  const {
    hscDetail = makeHscDetail(),
    modifierFeeImpact = null,
    afterHoursPremium = null,
    cmgpPremium = null,
    rrnpPremium = null,
    edSurcharge = null,
    rrnpEligible = false,
    modifierImpactFn,
  } = overrides;

  return {
    repo: {
      createAhcipDetail: vi.fn(async () => ({})),
      findAhcipDetailByClaimId: vi.fn(async (claimId: string, physicianId: string) => {
        if (claimId === CLAIM_ID && physicianId === PHYSICIAN_ID) {
          return {
            ahcipDetailId: '00000000-dddd-0000-0000-000000000001',
            claimId: CLAIM_ID,
            healthServiceCode: hscDetail?.code ?? '03.04A',
            baNumber: '12345',
            submittedFee: hscDetail?.baseFee ?? '38.56',
            assessedFee: null,
            assessmentExplanatoryCodes: null,
            modifier1: null,
            modifier2: null,
            modifier3: null,
            diagnosticCode: null,
            encounterType: 'FOLLOW_UP',
            calls: 1,
            timeSpent: null,
            shadowBillingFlag: false,
            pcpcmBasketFlag: false,
            afterHoursFlag: false,
            afterHoursType: null,
            claim: {
              claimId: CLAIM_ID,
              physicianId: PHYSICIAN_ID,
              patientId: '00000000-aaaa-0000-0000-000000000001',
              claimType: 'AHCIP',
              state: 'VALIDATED',
              dateOfService: '2026-01-15',
              createdAt: new Date(),
              updatedAt: new Date(),
              deletedAt: null,
            },
          };
        }
        return null;
      }),
      updateAhcipDetail: vi.fn(async () => undefined),
      findAhcipClaimWithDetails: vi.fn(async () => null),
      listAhcipClaimsForBatch: vi.fn(async () => []),
      updateAssessmentResult: vi.fn(async () => undefined),
      createAhcipBatch: vi.fn(async () => ({})),
      findBatchById: vi.fn(async () => null),
      updateBatchStatus: vi.fn(async () => undefined),
      listBatches: vi.fn(async () => ({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
      })),
      findNextBatchPreview: vi.fn(async () => []),
      findBatchesAwaitingResponse: vi.fn(async () => []),
      findClaimsByBatchId: vi.fn(async () => []),
      findBatchByWeek: vi.fn(async () => null),
      linkClaimsToBatch: vi.fn(async () => 0),
    } as any,
    feeRefData: {
      getHscDetail: vi.fn(async () => hscDetail),
      getModifierFeeImpact: modifierImpactFn
        ? vi.fn(modifierImpactFn)
        : vi.fn(async () => modifierFeeImpact),
      getAfterHoursPremium: vi.fn(async () => afterHoursPremium),
      getCmgpPremium: vi.fn(async () => cmgpPremium),
      getRrnpPremium: vi.fn(async () => rrnpPremium),
      getEdSurcharge: vi.fn(async () => edSurcharge),
    },
    feeProviderService: {
      isRrnpEligible: vi.fn(async () => rrnpEligible),
    },
  };
}

// ===========================================================================
// Tests
// ===========================================================================

describe('AHCIP Fee Calculation Integration', () => {
  // =========================================================================
  // Base fee from SOMB schedule
  // =========================================================================

  describe('Base fee from SOMB schedule', () => {
    it('returns base fee for a standard office visit HSC code', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ code: '03.04A', baseFee: '38.56' }),
      });
      const input = makeInput({ healthServiceCode: '03.04A' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('38.56');
      expect(result.total_fee).toBe('38.56');
      expect(result.calls).toBe(1);
    });

    it('returns base fee for a higher-value consultation code', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ code: '03.01A', baseFee: '138.34' }),
      });
      const input = makeInput({ healthServiceCode: '03.01A' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('138.34');
      expect(result.total_fee).toBe('138.34');
    });

    it('returns zero breakdown when HSC code not found', async () => {
      const deps = createMockFeeCalcDeps({ hscDetail: null });
      const input = makeInput({ healthServiceCode: 'INVALID' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('0.00');
      expect(result.total_fee).toBe('0.00');
      expect(result.modifier_adjustments).toEqual([]);
      expect(result.premiums).toEqual([]);
    });

    it('returns zero breakdown when HSC has no base fee', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: null }),
      });
      const input = makeInput();

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.total_fee).toBe('0.00');
    });

    it('multiplies base fee by call count', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
      });
      const input = makeInput({ calls: 3 });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('38.56');
      expect(result.calls).toBe(3);
      // 38.56 × 3 = 115.68
      expect(result.total_fee).toBe('115.68');
    });
  });

  // =========================================================================
  // Modifier fee impacts
  // =========================================================================

  describe('Modifier fee impacts', () => {
    it('TM modifier (shadow billing) produces $0 total', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
      });
      const input = makeInput({ modifier1: 'TM', shadowBillingFlag: true });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.total_fee).toBe(SHADOW_BILLING_FEE);
      expect(result.base_fee).toBe('38.56');
    });

    it('CMGP modifier adds premium when HSC qualifies', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        cmgpPremium: '15.00',
      });
      const input = makeInput({ modifier1: 'CMGP' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({ type: 'CMGP', amount: '15.00' });
      // 38.56 + 15.00 = 53.56
      expect(result.total_fee).toBe('53.56');
    });

    it('CMGP modifier has no effect when HSC does not qualify', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        cmgpPremium: null, // not qualifying
      });
      const input = makeInput({ modifier1: 'CMGP' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toEqual([]);
      expect(result.total_fee).toBe('38.56');
    });

    it('AFHR modifier adds after-hours premium when eligible', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        afterHoursPremium: '25.00',
      });
      const input = makeInput({
        modifier1: 'AFHR',
        afterHoursFlag: true,
        afterHoursType: 'EVENING',
      });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({
        type: 'AFTER_HOURS_EVENING',
        amount: '25.00',
      });
      // 38.56 + 25.00 = 63.56
      expect(result.total_fee).toBe('63.56');
    });

    it('LOCI modifier has no fee impact', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        // LOCI won't appear in modifier adjustments (skipped as it has no fee impact)
      });
      const input = makeInput({ modifier1: 'LOCI' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      // LOCI is not TM/AFHR so it will be looked up via getModifierFeeImpact
      // which returns null → no adjustment
      expect(result.total_fee).toBe('38.56');
    });

    it('percentage-based modifier applies correctly', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '100.00' }),
        modifierImpactFn: async (mod: string) => {
          if (mod === 'BMI') {
            return {
              modifierCode: 'BMI',
              calculationMethod: 'PERCENTAGE' as const,
              value: '0.15', // 15%
              priority: 1,
            };
          }
          return null;
        },
      });
      const input = makeInput({ modifier1: 'BMI' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.modifier_adjustments).toHaveLength(1);
      expect(result.modifier_adjustments[0].modifier).toBe('BMI');
      expect(result.modifier_adjustments[0].amount).toBe('15.00');
      expect(result.modifier_adjustments[0].effect).toContain('15%');
      // 100.00 + 15.00 = 115.00
      expect(result.total_fee).toBe('115.00');
    });

    it('additive modifier applies correctly', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '50.00' }),
        modifierImpactFn: async (mod: string) => {
          if (mod === 'ADD_MOD') {
            return {
              modifierCode: 'ADD_MOD',
              calculationMethod: 'ADDITIVE' as const,
              value: '20.00',
              priority: 1,
            };
          }
          return null;
        },
      });
      const input = makeInput({ modifier1: 'ADD_MOD' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.modifier_adjustments).toHaveLength(1);
      expect(result.modifier_adjustments[0].amount).toBe('20.00');
      // 50.00 + 20.00 = 70.00
      expect(result.total_fee).toBe('70.00');
    });

    it('override modifier replaces base fee', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '50.00' }),
        modifierImpactFn: async (mod: string) => {
          if (mod === 'OVERRIDE_MOD') {
            return {
              modifierCode: 'OVERRIDE_MOD',
              calculationMethod: 'OVERRIDE' as const,
              value: '75.00',
              priority: 1,
            };
          }
          return null;
        },
      });
      const input = makeInput({ modifier1: 'OVERRIDE_MOD' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      // Override adjustment = 75.00 - 50.00 = 25.00
      expect(result.modifier_adjustments).toHaveLength(1);
      expect(result.modifier_adjustments[0].amount).toBe('25.00');
      expect(result.modifier_adjustments[0].effect).toContain('Override');
      // 50.00 + 25.00 = 75.00
      expect(result.total_fee).toBe('75.00');
    });

    it('multiple modifiers applied in SOMB priority order', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '100.00' }),
        modifierImpactFn: async (mod: string) => {
          if (mod === 'HIGH_PRIO') {
            return {
              modifierCode: 'HIGH_PRIO',
              calculationMethod: 'ADDITIVE' as const,
              value: '10.00',
              priority: 1,
            };
          }
          if (mod === 'LOW_PRIO') {
            return {
              modifierCode: 'LOW_PRIO',
              calculationMethod: 'ADDITIVE' as const,
              value: '5.00',
              priority: 2,
            };
          }
          return null;
        },
      });
      const input = makeInput({ modifier1: 'LOW_PRIO', modifier2: 'HIGH_PRIO' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      // Both adjustments should be present
      expect(result.modifier_adjustments).toHaveLength(2);
      // Sorted by priority: HIGH_PRIO first
      expect(result.modifier_adjustments[0].modifier).toBe('HIGH_PRIO');
      expect(result.modifier_adjustments[1].modifier).toBe('LOW_PRIO');
      // 100.00 + 10.00 + 5.00 = 115.00
      expect(result.total_fee).toBe('115.00');
    });
  });

  // =========================================================================
  // RRNP premium
  // =========================================================================

  describe('RRNP premium', () => {
    it('adds RRNP premium for qualifying physician', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        rrnpEligible: true,
        rrnpPremium: '12.50',
      });
      const input = makeInput();

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.rrnp_premium).toBe('12.50');
      // 38.56 + 12.50 = 51.06
      expect(result.total_fee).toBe('51.06');
    });

    it('no RRNP premium for non-qualifying physician', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        rrnpEligible: false,
      });
      const input = makeInput();

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.rrnp_premium).toBeNull();
      expect(result.total_fee).toBe('38.56');
    });

    it('RRNP premium null when eligible but no rate found', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        rrnpEligible: true,
        rrnpPremium: null,
      });
      const input = makeInput();

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.rrnp_premium).toBeNull();
    });
  });

  // =========================================================================
  // Shadow billing
  // =========================================================================

  describe('Shadow billing', () => {
    it('produces $0 total fee', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '138.34' }),
      });
      const input = makeInput({ modifier1: 'TM', shadowBillingFlag: true });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.total_fee).toBe('0.00');
    });

    it('still reports base fee in breakdown for tracking', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '138.34' }),
      });
      const input = makeInput({ modifier1: 'TM', shadowBillingFlag: true });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('138.34');
    });

    it('still computes RRNP premium for tracking (but total stays $0)', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
        rrnpEligible: true,
        rrnpPremium: '12.50',
      });
      const input = makeInput({ modifier1: 'TM', shadowBillingFlag: true });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.rrnp_premium).toBe('12.50');
      expect(result.total_fee).toBe('0.00');
    });
  });

  // =========================================================================
  // PCPCM fee routing
  // =========================================================================

  describe('PCPCM fee routing', () => {
    it('in-basket code calculates fee normally', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', pcpcmBasket: 'IN_BASKET' }),
      });
      const input = makeInput({ pcpcmBasketFlag: true });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      // Fee is still calculated even for in-basket (for tracking)
      expect(result.base_fee).toBe('38.56');
      expect(result.total_fee).toBe('38.56');
    });

    it('out-of-basket code calculates as standard FFS', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '85.00', pcpcmBasket: 'OUT_OF_BASKET' }),
      });
      const input = makeInput({ pcpcmBasketFlag: false });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('85.00');
      expect(result.total_fee).toBe('85.00');
    });
  });

  // =========================================================================
  // After-hours premium
  // =========================================================================

  describe('After-hours premium', () => {
    it('evening premium applied for eligible HSC', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        afterHoursPremium: '25.00',
      });
      const input = makeInput({ afterHoursFlag: true, afterHoursType: 'EVENING' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({
        type: 'AFTER_HOURS_EVENING',
        amount: '25.00',
      });
    });

    it('weekend premium applied for eligible HSC', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        afterHoursPremium: '35.00',
      });
      const input = makeInput({ afterHoursFlag: true, afterHoursType: 'WEEKEND' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({
        type: 'AFTER_HOURS_WEEKEND',
        amount: '35.00',
      });
    });

    it('stat holiday premium applied for eligible HSC', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        afterHoursPremium: '50.00',
      });
      const input = makeInput({ afterHoursFlag: true, afterHoursType: 'STAT_HOLIDAY' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({
        type: 'AFTER_HOURS_STAT_HOLIDAY',
        amount: '50.00',
      });
    });

    it('no premium when HSC is not after-hours eligible', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: false }),
        afterHoursPremium: '25.00',
      });
      const input = makeInput({ afterHoursFlag: true, afterHoursType: 'EVENING' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toEqual([]);
      expect(result.total_fee).toBe('38.56');
    });

    it('no premium when after-hours flag not set', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        afterHoursPremium: '25.00',
      });
      const input = makeInput({ afterHoursFlag: false });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toEqual([]);
    });
  });

  // =========================================================================
  // ED surcharge
  // =========================================================================

  describe('ED surcharge', () => {
    it('adds ED surcharge for qualifying code with modifier', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', surchargeEligible: true }),
        edSurcharge: '10.00',
      });
      const input = makeInput({ modifier1: '13.99H' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({
        type: 'ED_SURCHARGE',
        amount: '10.00',
      });
      // 38.56 + 10.00 = 48.56
      expect(result.total_fee).toBe('48.56');
    });

    it('no surcharge without 13.99H modifier', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', surchargeEligible: true }),
        edSurcharge: '10.00',
      });
      const input = makeInput();

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toEqual([]);
    });

    it('no surcharge when HSC is not eligible', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', surchargeEligible: false }),
        edSurcharge: '10.00',
      });
      const input = makeInput({ modifier1: '13.99H' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      const edPrem = result.premiums.find((p) => p.type === 'ED_SURCHARGE');
      expect(edPrem).toBeUndefined();
    });
  });

  // =========================================================================
  // Combined fee scenarios
  // =========================================================================

  describe('Combined fee scenarios', () => {
    it('FFS with CMGP + after-hours + RRNP', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56', afterHoursEligible: true }),
        cmgpPremium: '15.00',
        afterHoursPremium: '25.00',
        rrnpEligible: true,
        rrnpPremium: '12.50',
      });
      const input = makeInput({
        modifier1: 'CMGP',
        modifier2: 'AFHR',
        afterHoursFlag: true,
        afterHoursType: 'EVENING',
      });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.base_fee).toBe('38.56');
      expect(result.premiums).toContainEqual({ type: 'CMGP', amount: '15.00' });
      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_EVENING', amount: '25.00' });
      expect(result.rrnp_premium).toBe('12.50');
      // 38.56 + 15.00 + 25.00 + 12.50 = 91.06
      expect(result.total_fee).toBe('91.06');
    });

    it('ED shift with surcharge + CMGP + after-hours', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({
          baseFee: '38.56',
          afterHoursEligible: true,
          surchargeEligible: true,
        }),
        cmgpPremium: '15.00',
        afterHoursPremium: '35.00',
        edSurcharge: '10.00',
      });
      const input = makeInput({
        modifier1: 'CMGP',
        modifier2: 'AFHR',
        modifier3: '13.99H',
        afterHoursFlag: true,
        afterHoursType: 'WEEKEND',
      });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      expect(result.premiums).toContainEqual({ type: 'CMGP', amount: '15.00' });
      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_WEEKEND', amount: '35.00' });
      expect(result.premiums).toContainEqual({ type: 'ED_SURCHARGE', amount: '10.00' });
      // 38.56 + 15.00 + 35.00 + 10.00 = 98.56
      expect(result.total_fee).toBe('98.56');
    });

    it('total fee cannot be negative', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '10.00' }),
        modifierImpactFn: async (mod: string) => {
          if (mod === 'NEG_MOD') {
            return {
              modifierCode: 'NEG_MOD',
              calculationMethod: 'ADDITIVE' as const,
              value: '-20.00',
              priority: 1,
            };
          }
          return null;
        },
      });
      const input = makeInput({ modifier1: 'NEG_MOD' });

      const result = await calculateFeePreview(deps, PHYSICIAN_ID, input);

      // 10.00 + (-20.00) = -10.00 → clamped to 0.00
      expect(result.total_fee).toBe('0.00');
    });
  });

  // =========================================================================
  // getFeeBreakdown (for existing claim)
  // =========================================================================

  describe('getFeeBreakdown', () => {
    it('returns breakdown for existing physician-owned claim', async () => {
      const deps = createMockFeeCalcDeps({
        hscDetail: makeHscDetail({ baseFee: '38.56' }),
      });

      const result = await getFeeBreakdown(deps, CLAIM_ID, PHYSICIAN_ID);

      expect(result.base_fee).toBe('38.56');
      expect(result.total_fee).toBe('38.56');
      expect(result).toHaveProperty('modifier_adjustments');
      expect(result).toHaveProperty('premiums');
    });

    it('throws when claim not found (different physician)', async () => {
      const deps = createMockFeeCalcDeps();
      const otherPhysician = '00000000-1111-0000-0000-000000000099';

      await expect(getFeeBreakdown(deps, CLAIM_ID, otherPhysician)).rejects.toThrow('Claim not found');
    });

    it('throws when claim does not exist', async () => {
      const deps = createMockFeeCalcDeps();
      const nonExistentClaim = '00000000-9999-0000-0000-000000000099';

      await expect(getFeeBreakdown(deps, nonExistentClaim, PHYSICIAN_ID)).rejects.toThrow('Claim not found');
    });
  });
});
