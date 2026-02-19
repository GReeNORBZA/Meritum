import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createDashboardQueryRepository } from './dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const PERIOD_START = '2026-01-01';
const PERIOD_END = '2026-01-31';
const PRIOR_START = '2025-12-01';
const PRIOR_END = '2025-12-31';

// ---------------------------------------------------------------------------
// Mock DB factory
// ---------------------------------------------------------------------------

function createMockDb() {
  const executeFn = vi.fn();
  const db = { execute: executeFn } as any;
  return { db, executeFn };
}

function rows<T>(data: T[]): { rows: T[] } {
  return { rows: data };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DashboardQueryRepository', () => {
  let executeFn: ReturnType<typeof vi.fn>;
  let repo: ReturnType<typeof createDashboardQueryRepository>;

  beforeEach(() => {
    const mock = createMockDb();
    executeFn = mock.executeFn;
    repo = createDashboardQueryRepository(mock.db);
  });

  // =========================================================================
  // computeRevenueMetrics
  // =========================================================================

  describe('computeRevenueMetrics', () => {
    it('returns correct revenue totals from paid claims', async () => {
      // 1. Total revenue
      executeFn.mockResolvedValueOnce(
        rows([{ total_revenue: '12500.00', total_submitted: '13000.00', claim_count: '25' }]),
      );
      // 2. Monthly trend
      executeFn.mockResolvedValueOnce(
        rows([
          { month: '2026-01', revenue: '12500.00', count: '25' },
        ]),
      );
      // 3. By BA
      executeFn.mockResolvedValueOnce(
        rows([
          { ba_number: 'BA001', revenue: '8000.00', count: '15' },
          { ba_number: 'BA002', revenue: '4500.00', count: '10' },
        ]),
      );
      // 4. Top HSC codes
      executeFn.mockResolvedValueOnce(
        rows([
          { hsc_code: '03.04A', revenue: '5000.00', count: '10' },
          { hsc_code: '03.05A', revenue: '3500.00', count: '8' },
        ]),
      );
      // 5. Pending pipeline
      executeFn.mockResolvedValueOnce(
        rows([{ pipeline_value: '2500.00', pipeline_count: '5' }]),
      );

      const result = await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.totalRevenue).toBe('12500.00');
      expect(result.totalSubmitted).toBe('13000.00');
      expect(result.claimCount).toBe(25);
      expect(result.monthlyTrend).toHaveLength(1);
      expect(result.monthlyTrend[0]).toEqual({ month: '2026-01', revenue: '12500.00', count: 25 });
      expect(result.byBa).toHaveLength(2);
      expect(result.byBa[0].baNumber).toBe('BA001');
      expect(result.byBa[0].revenue).toBe('8000.00');
      expect(result.topHscCodes).toHaveLength(2);
      expect(result.topHscCodes[0].hscCode).toBe('03.04A');
      expect(result.pendingPipeline).toEqual({ value: '2500.00', count: 5 });
    });

    it('returns zeros when no paid claims exist', async () => {
      executeFn.mockResolvedValueOnce(rows([])); // total — empty
      executeFn.mockResolvedValueOnce(rows([])); // trend — empty
      executeFn.mockResolvedValueOnce(rows([])); // BA — empty
      executeFn.mockResolvedValueOnce(rows([])); // HSC — empty
      executeFn.mockResolvedValueOnce(rows([])); // pipeline — empty

      const result = await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.totalRevenue).toBe('0');
      expect(result.totalSubmitted).toBe('0');
      expect(result.claimCount).toBe(0);
      expect(result.monthlyTrend).toHaveLength(0);
      expect(result.byBa).toHaveLength(0);
      expect(result.topHscCodes).toHaveLength(0);
      expect(result.pendingPipeline).toEqual({ value: '0', count: 0 });
    });

    it('passes providerId to all queries (provider scoping)', async () => {
      executeFn.mockResolvedValue(rows([]));

      await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      // All 5 queries should have been called
      expect(executeFn).toHaveBeenCalledTimes(5);
      // Verify each SQL template includes the provider ID
      for (let i = 0; i < 5; i++) {
        const sqlTemplate = executeFn.mock.calls[i][0];
        expect(sqlContainsValue(sqlTemplate, PROVIDER_A)).toBe(true);
      }
    });

    it('applies claim type filter when provided', async () => {
      executeFn.mockResolvedValue(rows([]));

      await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END, {
        claimType: 'AHCIP',
      });

      expect(executeFn).toHaveBeenCalledTimes(5);
    });

    it('applies BA number filter when provided', async () => {
      executeFn.mockResolvedValue(rows([]));

      await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END, {
        baNumber: 'BA001',
      });

      expect(executeFn).toHaveBeenCalledTimes(5);
    });

    it('returns multiple months in trend for multi-month periods', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{ total_revenue: '20000.00', total_submitted: '22000.00', claim_count: '40' }]),
      );
      executeFn.mockResolvedValueOnce(
        rows([
          { month: '2026-01', revenue: '8000.00', count: '16' },
          { month: '2026-02', revenue: '12000.00', count: '24' },
        ]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([{ pipeline_value: '0', pipeline_count: '0' }]));

      const result = await repo.computeRevenueMetrics(PROVIDER_A, '2026-01-01', '2026-02-28');

      expect(result.monthlyTrend).toHaveLength(2);
      expect(result.monthlyTrend[0].month).toBe('2026-01');
      expect(result.monthlyTrend[1].month).toBe('2026-02');
      expect(result.monthlyTrend[0].count).toBe(16);
      expect(result.monthlyTrend[1].count).toBe(24);
    });
  });

  // =========================================================================
  // computeRejectionMetrics
  // =========================================================================

  describe('computeRejectionMetrics', () => {
    it('computes rejection rate correctly', async () => {
      // Totals: 80 assessed, 15 rejected, 5 adjusted → rate = 15 / (80+15+5) = 15%
      executeFn.mockResolvedValueOnce(
        rows([{ total_assessed: '80', total_rejected: '15', total_adjusted: '5' }]),
      );
      // By explanatory code
      executeFn.mockResolvedValueOnce(
        rows([
          { code: 'R01', count: '8' },
          { code: 'R05', count: '7' },
        ]),
      );
      // By HSC code
      executeFn.mockResolvedValueOnce(
        rows([
          { hsc_code: '03.04A', total: '20', rejected_count: '5' },
          { hsc_code: '03.05A', total: '30', rejected_count: '10' },
        ]),
      );
      // Resolution funnel
      executeFn.mockResolvedValueOnce(
        rows([{ rejected: '15', written_off: '3' }]),
      );

      const result = await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.totalAssessed).toBe(80);
      expect(result.totalRejected).toBe(15);
      expect(result.totalAdjusted).toBe(5);
      expect(result.rejectionRate).toBe('15.00');
      expect(result.byExplanatoryCode).toHaveLength(2);
      expect(result.byExplanatoryCode[0]).toEqual({ code: 'R01', count: 8 });
      expect(result.byHscCode).toHaveLength(2);
      expect(result.byHscCode[0]).toEqual({ hscCode: '03.04A', count: 5, rate: '25.00' });
      expect(result.byHscCode[1]).toEqual({ hscCode: '03.05A', count: 10, rate: '33.33' });
      expect(result.resolutionFunnel.rejected).toBe(15);
      expect(result.resolutionFunnel.writtenOff).toBe(3);
    });

    it('returns 0.00 rejection rate when no claims decided', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{ total_assessed: '0', total_rejected: '0', total_adjusted: '0' }]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([{ rejected: '0', written_off: '0' }]));

      const result = await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.rejectionRate).toBe('0.00');
      expect(result.totalAssessed).toBe(0);
      expect(result.totalRejected).toBe(0);
    });

    it('handles rejection rate with only rejections (100%)', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{ total_assessed: '0', total_rejected: '10', total_adjusted: '0' }]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([{ rejected: '10', written_off: '0' }]));

      const result = await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.rejectionRate).toBe('100.00');
    });

    it('calculates per-HSC rejection rates correctly', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{ total_assessed: '50', total_rejected: '5', total_adjusted: '0' }]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      // HSC code with 1 out of 10 = 10% rejection
      executeFn.mockResolvedValueOnce(
        rows([{ hsc_code: '03.04A', total: '10', rejected_count: '1' }]),
      );
      executeFn.mockResolvedValueOnce(rows([{ rejected: '5', written_off: '0' }]));

      const result = await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.byHscCode[0].rate).toBe('10.00');
    });

    it('handles empty results gracefully', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.totalAssessed).toBe(0);
      expect(result.totalRejected).toBe(0);
      expect(result.totalAdjusted).toBe(0);
      expect(result.rejectionRate).toBe('0.00');
      expect(result.byExplanatoryCode).toHaveLength(0);
      expect(result.byHscCode).toHaveLength(0);
      expect(result.resolutionFunnel.rejected).toBe(0);
      expect(result.resolutionFunnel.writtenOff).toBe(0);
    });
  });

  // =========================================================================
  // computeAgingMetrics
  // =========================================================================

  describe('computeAgingMetrics', () => {
    it('returns claims bucketed into correct aging brackets', async () => {
      // Aging brackets
      executeFn.mockResolvedValueOnce(
        rows([
          { bracket_label: '0-30 days', min_days: '0', max_days: '30', count: '10', total_value: '5000.00' },
          { bracket_label: '31-60 days', min_days: '31', max_days: '60', count: '5', total_value: '2500.00' },
          { bracket_label: '61-90 days', min_days: '61', max_days: '90', count: '3', total_value: '1500.00' },
          { bracket_label: '90+ days', min_days: '91', max_days: null, count: '2', total_value: '1000.00' },
        ]),
      );
      // Approaching deadline
      executeFn.mockResolvedValueOnce(
        rows([
          { claim_id: 'c-1', deadline: '2026-02-01', days_remaining: '3' },
        ]),
      );
      // Expired
      executeFn.mockResolvedValueOnce(rows([{ count: '1' }]));
      // Avg resolution
      executeFn.mockResolvedValueOnce(rows([{ avg_days: '14.5' }]));
      // Stale claims
      executeFn.mockResolvedValueOnce(rows([{ count: '4' }]));

      const result = await repo.computeAgingMetrics(PROVIDER_A);

      expect(result.brackets).toHaveLength(4);
      expect(result.brackets[0]).toEqual({
        label: '0-30 days',
        minDays: 0,
        maxDays: 30,
        count: 10,
        value: '5000.00',
      });
      expect(result.brackets[3]).toEqual({
        label: '90+ days',
        minDays: 91,
        maxDays: null,
        count: 2,
        value: '1000.00',
      });
      expect(result.approachingDeadline.count).toBe(1);
      expect(result.approachingDeadline.claims[0].claimId).toBe('c-1');
      expect(result.approachingDeadline.claims[0].daysRemaining).toBe(3);
      expect(result.expiredClaims.count).toBe(1);
      expect(result.avgResolutionDays).toBe(15); // Math.round(14.5)
      expect(result.staleClaims.count).toBe(4);
    });

    it('returns null avg resolution when no paid claims exist', async () => {
      executeFn.mockResolvedValueOnce(rows([])); // aging brackets
      executeFn.mockResolvedValueOnce(rows([])); // approaching deadline
      executeFn.mockResolvedValueOnce(rows([{ count: '0' }])); // expired
      executeFn.mockResolvedValueOnce(rows([{ avg_days: null }])); // avg resolution
      executeFn.mockResolvedValueOnce(rows([{ count: '0' }])); // stale

      const result = await repo.computeAgingMetrics(PROVIDER_A);

      expect(result.avgResolutionDays).toBeNull();
      expect(result.brackets).toHaveLength(0);
      expect(result.approachingDeadline.count).toBe(0);
      expect(result.expiredClaims.count).toBe(0);
      expect(result.staleClaims.count).toBe(0);
    });

    it('handles multiple approaching-deadline claims', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(
        rows([
          { claim_id: 'c-1', deadline: '2026-02-01', days_remaining: '3' },
          { claim_id: 'c-2', deadline: '2026-02-03', days_remaining: '5' },
          { claim_id: 'c-3', deadline: '2026-02-05', days_remaining: '7' },
        ]),
      );
      executeFn.mockResolvedValueOnce(rows([{ count: '0' }]));
      executeFn.mockResolvedValueOnce(rows([{ avg_days: null }]));
      executeFn.mockResolvedValueOnce(rows([{ count: '0' }]));

      const result = await repo.computeAgingMetrics(PROVIDER_A);

      expect(result.approachingDeadline.count).toBe(3);
      expect(result.approachingDeadline.claims).toHaveLength(3);
    });
  });

  // =========================================================================
  // computeWcbMetrics
  // =========================================================================

  describe('computeWcbMetrics', () => {
    it('returns WCB metrics grouped by form type', async () => {
      // By form type
      executeFn.mockResolvedValueOnce(
        rows([
          { form_id: 'C050E', count: '10', revenue: '3500.00' },
          { form_id: 'C151', count: '5', revenue: '2000.00' },
        ]),
      );
      // Timing tier distribution
      executeFn.mockResolvedValueOnce(
        rows([
          { tier: 'INITIAL', count: '8' },
          { tier: 'FOLLOWUP', count: '7' },
        ]),
      );
      // Fee by timing tier
      executeFn.mockResolvedValueOnce(
        rows([
          { tier: 'INITIAL', total_fee: '2800.00', avg_fee: '350.00', count: '8' },
          { tier: 'FOLLOWUP', total_fee: '1400.00', avg_fee: '200.00', count: '7' },
        ]),
      );
      // Revenue trend
      executeFn.mockResolvedValueOnce(
        rows([
          { month: '2026-01', revenue: '5500.00', count: '15' },
        ]),
      );
      // Rejection rate
      executeFn.mockResolvedValueOnce(
        rows([{ total_claims: '20', total_rejected: '2' }]),
      );

      const result = await repo.computeWcbMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.byFormType).toHaveLength(2);
      expect(result.byFormType[0]).toEqual({ formId: 'C050E', count: 10, revenue: '3500.00' });
      expect(result.timingTierDistribution).toHaveLength(2);
      expect(result.feeByTimingTier).toHaveLength(2);
      expect(result.feeByTimingTier[0].avgFee).toBe('350.00');
      expect(result.revenueTrend[0].month).toBe('2026-01');
      expect(result.rejectionRate).toBe('10.00');
      expect(result.totalClaims).toBe(20);
      expect(result.totalRejected).toBe(2);
    });

    it('returns 0.00 rejection rate when no WCB claims decided', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([{ total_claims: '0', total_rejected: '0' }]));

      const result = await repo.computeWcbMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.rejectionRate).toBe('0.00');
      expect(result.totalClaims).toBe(0);
      expect(result.totalRejected).toBe(0);
      expect(result.byFormType).toHaveLength(0);
    });

    it('handles empty results for all WCB sub-queries', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeWcbMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.byFormType).toHaveLength(0);
      expect(result.timingTierDistribution).toHaveLength(0);
      expect(result.feeByTimingTier).toHaveLength(0);
      expect(result.revenueTrend).toHaveLength(0);
      expect(result.totalClaims).toBe(0);
    });
  });

  // =========================================================================
  // computeAiCoachMetrics
  // =========================================================================

  describe('computeAiCoachMetrics', () => {
    it('computes acceptance rate and revenue recovered', async () => {
      // Overall
      executeFn.mockResolvedValueOnce(
        rows([{
          total_generated: '100',
          total_accepted: '60',
          total_dismissed: '40',
          revenue_recovered: '12000.00',
        }]),
      );
      // By category
      executeFn.mockResolvedValueOnce(
        rows([
          { category: 'MODIFIER_ADD', generated: '40', accepted: '30', revenue: '6000.00' },
          { category: 'FEE_OPTIMIZATION', generated: '60', accepted: '30', revenue: '6000.00' },
        ]),
      );
      // Top accepted rules
      executeFn.mockResolvedValueOnce(
        rows([
          { rule_id: 'r-1', rule_name: 'Add time modifier', accepted_count: '15', revenue: '3000.00' },
          { rule_id: 'r-2', rule_name: 'After hours premium', accepted_count: '10', revenue: '2000.00' },
        ]),
      );
      // Suppressed rules
      executeFn.mockResolvedValueOnce(
        rows([
          { rule_id: 'r-3', rule_name: 'Low value suggestion' },
        ]),
      );

      const result = await repo.computeAiCoachMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.acceptanceRate).toBe('60.00');
      expect(result.totalGenerated).toBe(100);
      expect(result.totalAccepted).toBe(60);
      expect(result.totalDismissed).toBe(40);
      expect(result.revenueRecovered).toBe('12000.00');
      expect(result.byCategory).toHaveLength(2);
      expect(result.byCategory[0].category).toBe('MODIFIER_ADD');
      expect(result.byCategory[0].rate).toBe('75.00');
      expect(result.byCategory[1].rate).toBe('50.00');
      expect(result.topAcceptedRules).toHaveLength(2);
      expect(result.topAcceptedRules[0].ruleName).toBe('Add time modifier');
      expect(result.suppressedRules).toHaveLength(1);
      expect(result.suppressedRules[0].ruleName).toBe('Low value suggestion');
    });

    it('returns 0.00 acceptance rate when no suggestions generated', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{
          total_generated: '0',
          total_accepted: '0',
          total_dismissed: '0',
          revenue_recovered: '0',
        }]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeAiCoachMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.acceptanceRate).toBe('0.00');
      expect(result.totalGenerated).toBe(0);
      expect(result.totalAccepted).toBe(0);
      expect(result.revenueRecovered).toBe('0');
      expect(result.byCategory).toHaveLength(0);
      expect(result.topAcceptedRules).toHaveLength(0);
      expect(result.suppressedRules).toHaveLength(0);
    });

    it('handles category with 0 generated (avoids division by zero)', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{
          total_generated: '10',
          total_accepted: '5',
          total_dismissed: '5',
          revenue_recovered: '500.00',
        }]),
      );
      executeFn.mockResolvedValueOnce(
        rows([
          { category: 'EMPTY_CATEGORY', generated: '0', accepted: '0', revenue: '0' },
        ]),
      );
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeAiCoachMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.byCategory[0].rate).toBe('0.00');
    });

    it('handles empty overall result gracefully', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeAiCoachMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.acceptanceRate).toBe('0.00');
      expect(result.totalGenerated).toBe(0);
    });
  });

  // =========================================================================
  // computeMultiSiteMetrics
  // =========================================================================

  describe('computeMultiSiteMetrics', () => {
    it('returns per-location metrics with rejection rates', async () => {
      executeFn.mockResolvedValueOnce(
        rows([
          {
            location_id: 'loc-1',
            location_name: 'Main Clinic',
            revenue: '10000.00',
            claim_count: '20',
            total_decided: '18',
            rejected_count: '2',
            rrnp_premium: '50.00',
          },
          {
            location_id: 'loc-2',
            location_name: 'Satellite Office',
            revenue: '5000.00',
            claim_count: '10',
            total_decided: '9',
            rejected_count: '1',
            rrnp_premium: '0',
          },
        ]),
      );

      const result = await repo.computeMultiSiteMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.locations).toHaveLength(2);
      expect(result.locations[0]).toEqual({
        locationId: 'loc-1',
        locationName: 'Main Clinic',
        revenue: '10000.00',
        claimCount: 20,
        rejectionRate: '11.11',
        rrnpPremium: '50.00',
      });
      expect(result.locations[1].rejectionRate).toBe('11.11');
    });

    it('returns 0.00 rejection rate when no decided claims at a location', async () => {
      executeFn.mockResolvedValueOnce(
        rows([
          {
            location_id: 'loc-1',
            location_name: 'New Clinic',
            revenue: '0',
            claim_count: '0',
            total_decided: '0',
            rejected_count: '0',
            rrnp_premium: '0',
          },
        ]),
      );

      const result = await repo.computeMultiSiteMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.locations[0].rejectionRate).toBe('0.00');
    });

    it('returns empty locations array when no locations exist', async () => {
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeMultiSiteMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(result.locations).toHaveLength(0);
    });

    it('accepts optional locationIds filter', async () => {
      executeFn.mockResolvedValueOnce(
        rows([
          {
            location_id: 'loc-1',
            location_name: 'Main Clinic',
            revenue: '10000.00',
            claim_count: '20',
            total_decided: '18',
            rejected_count: '2',
            rrnp_premium: '50.00',
          },
        ]),
      );

      const result = await repo.computeMultiSiteMetrics(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        ['loc-1'],
      );

      expect(result.locations).toHaveLength(1);
      expect(result.locations[0].locationId).toBe('loc-1');
    });
  });

  // =========================================================================
  // computeKpis
  // =========================================================================

  describe('computeKpis', () => {
    it('computes KPIs with prior period comparison and deltas', async () => {
      // Current period
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '15000.00',
          claims_submitted: '30',
          total_decided: '25',
          rejected: '5',
          avg_fee: '600.00',
          pending: '3000.00',
        }]),
      );
      // Prior period
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '12000.00',
          claims_submitted: '25',
          total_decided: '20',
          rejected: '4',
          avg_fee: '480.00',
          pending: '2000.00',
        }]),
      );

      const result = await repo.computeKpis(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        PRIOR_START,
        PRIOR_END,
      );

      expect(result.totalRevenue).toBe('15000.00');
      expect(result.priorRevenue).toBe('12000.00');
      // Revenue delta: ((15000 - 12000) / 12000) * 100 = 25%
      expect(result.revenueDelta).toBe('25.00');
      expect(result.claimsSubmitted).toBe(30);
      expect(result.priorClaimsSubmitted).toBe(25);
      // Claims delta: ((30 - 25) / 25) * 100 = 20%
      expect(result.claimsDelta).toBe('20.00');
      // Current rejection: 5/25 = 20%
      expect(result.rejectionRate).toBe('20.00');
      // Prior rejection: 4/20 = 20%
      expect(result.priorRejectionRate).toBe('20.00');
      // Rejection delta: 0%
      expect(result.rejectionDelta).toBe('0.00');
      expect(result.avgFeePerClaim).toBe('600.00');
      expect(result.priorAvgFee).toBe('480.00');
      expect(result.pendingPipeline).toBe('3000.00');
      expect(result.priorPendingPipeline).toBe('2000.00');
    });

    it('handles zero prior period values (delta = 100% when current > 0)', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '5000.00',
          claims_submitted: '10',
          total_decided: '8',
          rejected: '2',
          avg_fee: '500.00',
          pending: '1000.00',
        }]),
      );
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '0',
          claims_submitted: '0',
          total_decided: '0',
          rejected: '0',
          avg_fee: '0.00',
          pending: '0',
        }]),
      );

      const result = await repo.computeKpis(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        PRIOR_START,
        PRIOR_END,
      );

      expect(result.revenueDelta).toBe('100.00');
      expect(result.claimsDelta).toBe('100.00');
    });

    it('handles both periods with zero values (delta = 0%)', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '0',
          claims_submitted: '0',
          total_decided: '0',
          rejected: '0',
          avg_fee: '0.00',
          pending: '0',
        }]),
      );
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '0',
          claims_submitted: '0',
          total_decided: '0',
          rejected: '0',
          avg_fee: '0.00',
          pending: '0',
        }]),
      );

      const result = await repo.computeKpis(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        PRIOR_START,
        PRIOR_END,
      );

      expect(result.revenueDelta).toBe('0.00');
      expect(result.claimsDelta).toBe('0.00');
      expect(result.rejectionRate).toBe('0.00');
      expect(result.priorRejectionRate).toBe('0.00');
    });

    it('handles empty result rows gracefully', async () => {
      executeFn.mockResolvedValueOnce(rows([]));
      executeFn.mockResolvedValueOnce(rows([]));

      const result = await repo.computeKpis(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        PRIOR_START,
        PRIOR_END,
      );

      expect(result.totalRevenue).toBe('0.00');
      expect(result.priorRevenue).toBe('0.00');
      expect(result.revenueDelta).toBe('0.00');
      expect(result.claimsSubmitted).toBe(0);
      expect(result.rejectionRate).toBe('0.00');
    });

    it('computes negative delta when current period is lower', async () => {
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '8000.00',
          claims_submitted: '15',
          total_decided: '12',
          rejected: '3',
          avg_fee: '533.33',
          pending: '1000.00',
        }]),
      );
      executeFn.mockResolvedValueOnce(
        rows([{
          revenue: '10000.00',
          claims_submitted: '20',
          total_decided: '15',
          rejected: '5',
          avg_fee: '500.00',
          pending: '2000.00',
        }]),
      );

      const result = await repo.computeKpis(
        PROVIDER_A,
        PERIOD_START,
        PERIOD_END,
        PRIOR_START,
        PRIOR_END,
      );

      // Revenue delta: (8000-10000)/10000 * 100 = -20%
      expect(result.revenueDelta).toBe('-20.00');
      // Claims delta: (15-20)/20 * 100 = -25%
      expect(result.claimsDelta).toBe('-25.00');
      // Pipeline delta: (1000-2000)/2000 * 100 = -50%
      expect(result.pipelineDelta).toBe('-50.00');
    });
  });

  // =========================================================================
  // Provider scoping verification (cross-cutting)
  // =========================================================================

  describe('provider scoping', () => {
    it('computeRevenueMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeRevenueMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      // Every query must include providerId as a parameterized value
      expect(executeFn).toHaveBeenCalledTimes(5);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeRejectionMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeRejectionMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(executeFn).toHaveBeenCalledTimes(4);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeAgingMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeAgingMetrics(PROVIDER_A);

      expect(executeFn).toHaveBeenCalledTimes(5);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeWcbMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeWcbMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(executeFn).toHaveBeenCalledTimes(5);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeAiCoachMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeAiCoachMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(executeFn).toHaveBeenCalledTimes(4);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeMultiSiteMetrics passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeMultiSiteMetrics(PROVIDER_A, PERIOD_START, PERIOD_END);

      expect(executeFn).toHaveBeenCalledTimes(1);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });

    it('computeKpis passes providerId in SQL parameters', async () => {
      executeFn.mockResolvedValue(rows([]));
      await repo.computeKpis(PROVIDER_A, PERIOD_START, PERIOD_END, PRIOR_START, PRIOR_END);

      expect(executeFn).toHaveBeenCalledTimes(2);
      for (const call of executeFn.mock.calls) {
        expect(sqlContainsValue(call[0], PROVIDER_A)).toBe(true);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// Helper: check if a drizzle sql template contains a specific value
// Uses JSON.stringify to serialize the template and check for the string.
// This works because provider IDs are UUID strings that appear uniquely.
// ---------------------------------------------------------------------------

function sqlContainsValue(sqlTemplate: any, value: string): boolean {
  try {
    const serialized = JSON.stringify(sqlTemplate);
    return serialized.includes(value);
  } catch {
    // Circular reference — walk manually
    return stringifyWithCircular(sqlTemplate).includes(value);
  }
}

function stringifyWithCircular(obj: any, visited = new WeakSet()): string {
  if (obj === null || obj === undefined) return '';
  if (typeof obj === 'string') return obj;
  if (typeof obj !== 'object') return String(obj);
  if (visited.has(obj)) return '';
  visited.add(obj);

  const parts: string[] = [];
  if (Array.isArray(obj)) {
    for (const item of obj) {
      parts.push(stringifyWithCircular(item, visited));
    }
  } else {
    for (const key of Object.keys(obj)) {
      parts.push(stringifyWithCircular(obj[key], visited));
    }
  }
  return parts.join(' ');
}
