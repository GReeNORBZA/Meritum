// ============================================================================
// Domain 8: Dashboard Query Repository
// Read-only queries against claim, provider, and intelligence tables.
// All queries scoped to provider_id. No INSERT/UPDATE/DELETE on foreign tables.
// ============================================================================

import { eq, and, sql, between, inArray } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { claims } from '@meritum/shared/schemas/db/claim.schema.js';
import { ahcipClaimDetails } from '@meritum/shared/schemas/db/ahcip.schema.js';
import {
  wcbClaimDetails,
  wcbInvoiceLines,
} from '@meritum/shared/schemas/db/wcb.schema.js';
import {
  practiceLocations,
  businessArrangements,
} from '@meritum/shared/schemas/db/provider.schema.js';
import {
  aiSuggestionEvents,
  aiProviderLearning,
  aiRules,
} from '@meritum/shared/schemas/db/intelligence.schema.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface RevenueMetrics {
  totalRevenue: string;
  totalSubmitted: string;
  claimCount: number;
  monthlyTrend: Array<{ month: string; revenue: string; count: number }>;
  byBa: Array<{ baNumber: string; revenue: string; count: number }>;
  topHscCodes: Array<{ hscCode: string; revenue: string; count: number }>;
  pendingPipeline: { value: string; count: number };
}

export interface RejectionMetrics {
  totalAssessed: number;
  totalRejected: number;
  totalAdjusted: number;
  rejectionRate: string;
  byExplanatoryCode: Array<{ code: string; count: number }>;
  byHscCode: Array<{ hscCode: string; count: number; rate: string }>;
  resolutionFunnel: {
    rejected: number;
    resubmitted: number;
    paidOnResubmission: number;
    writtenOff: number;
  };
}

export interface AgingMetrics {
  brackets: Array<{ label: string; minDays: number; maxDays: number | null; count: number; value: string }>;
  approachingDeadline: { count: number; claims: Array<{ claimId: string; deadline: string; daysRemaining: number }> };
  expiredClaims: { count: number };
  avgResolutionDays: number | null;
  staleClaims: { count: number };
}

export interface WcbMetrics {
  byFormType: Array<{ formId: string; count: number; revenue: string }>;
  timingTierDistribution: Array<{ tier: string; count: number }>;
  feeByTimingTier: Array<{ tier: string; totalFee: string; avgFee: string; count: number }>;
  revenueTrend: Array<{ month: string; revenue: string; count: number }>;
  rejectionRate: string;
  totalClaims: number;
  totalRejected: number;
}

export interface AiCoachMetrics {
  acceptanceRate: string;
  totalGenerated: number;
  totalAccepted: number;
  totalDismissed: number;
  revenueRecovered: string;
  byCategory: Array<{ category: string; generated: number; accepted: number; rate: string; revenue: string }>;
  topAcceptedRules: Array<{ ruleId: string; ruleName: string; acceptedCount: number; revenue: string }>;
  suppressedRules: Array<{ ruleId: string; ruleName: string }>;
}

export interface MultiSiteMetrics {
  locations: Array<{
    locationId: string;
    locationName: string;
    revenue: string;
    claimCount: number;
    rejectionRate: string;
    rrnpPremium: string;
  }>;
}

export interface KpiMetrics {
  totalRevenue: string;
  priorRevenue: string;
  revenueDelta: string;
  claimsSubmitted: number;
  priorClaimsSubmitted: number;
  claimsDelta: string;
  rejectionRate: string;
  priorRejectionRate: string;
  rejectionDelta: string;
  avgFeePerClaim: string;
  priorAvgFee: string;
  avgFeeDelta: string;
  pendingPipeline: string;
  priorPendingPipeline: string;
  pipelineDelta: string;
}

export interface DashboardQueryFilters {
  claimType?: 'AHCIP' | 'WCB' | 'BOTH';
  baNumber?: string;
  locationId?: string;
}

// ---------------------------------------------------------------------------
// Repository factory
// ---------------------------------------------------------------------------

export function createDashboardQueryRepository(db: NodePgDatabase) {
  return {
    async computeRevenueMetrics(
      providerId: string,
      periodStart: string,
      periodEnd: string,
      filters?: DashboardQueryFilters,
    ): Promise<RevenueMetrics> {
      const claimTypeCondition = buildClaimTypeCondition(filters?.claimType);
      const baCondition = filters?.baNumber
        ? sql`AND acd.ba_number = ${filters.baNumber}`
        : sql``;

      // Total revenue from paid AHCIP claims
      const revenueResult = await db.execute<{
        total_revenue: string;
        total_submitted: string;
        claim_count: string;
      }>(sql`
        SELECT
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)), 0)::TEXT AS total_revenue,
          COALESCE(SUM(CAST(acd.submitted_fee AS NUMERIC)), 0)::TEXT AS total_submitted,
          COUNT(*)::TEXT AS claim_count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state = 'PAID'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
          ${baCondition}
      `);

      const rev = revenueResult.rows[0] ?? { total_revenue: '0', total_submitted: '0', claim_count: '0' };

      // Monthly trend
      const trendResult = await db.execute<{
        month: string;
        revenue: string;
        count: string;
      }>(sql`
        SELECT
          TO_CHAR(c.date_of_service, 'YYYY-MM') AS month,
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)), 0)::TEXT AS revenue,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state = 'PAID'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
          ${baCondition}
        GROUP BY TO_CHAR(c.date_of_service, 'YYYY-MM')
        ORDER BY month
      `);

      // By BA breakdown
      const baResult = await db.execute<{
        ba_number: string;
        revenue: string;
        count: string;
      }>(sql`
        SELECT
          acd.ba_number,
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)), 0)::TEXT AS revenue,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state = 'PAID'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
        GROUP BY acd.ba_number
        ORDER BY revenue DESC
      `);

      // Top 10 HSC codes
      const hscResult = await db.execute<{
        hsc_code: string;
        revenue: string;
        count: string;
      }>(sql`
        SELECT
          acd.health_service_code AS hsc_code,
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)), 0)::TEXT AS revenue,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state = 'PAID'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
          ${baCondition}
        GROUP BY acd.health_service_code
        ORDER BY SUM(CAST(acd.assessed_fee AS NUMERIC)) DESC
        LIMIT 10
      `);

      // Pending pipeline (QUEUED + SUBMITTED)
      const pipelineResult = await db.execute<{
        pipeline_value: string;
        pipeline_count: string;
      }>(sql`
        SELECT
          COALESCE(SUM(CAST(acd.submitted_fee AS NUMERIC)), 0)::TEXT AS pipeline_value,
          COUNT(*)::TEXT AS pipeline_count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('QUEUED', 'SUBMITTED')
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
          ${baCondition}
      `);

      const pipeline = pipelineResult.rows[0] ?? { pipeline_value: '0', pipeline_count: '0' };

      return {
        totalRevenue: rev.total_revenue,
        totalSubmitted: rev.total_submitted,
        claimCount: parseInt(rev.claim_count, 10),
        monthlyTrend: trendResult.rows.map((r) => ({
          month: r.month,
          revenue: r.revenue,
          count: parseInt(r.count, 10),
        })),
        byBa: baResult.rows.map((r) => ({
          baNumber: r.ba_number,
          revenue: r.revenue,
          count: parseInt(r.count, 10),
        })),
        topHscCodes: hscResult.rows.map((r) => ({
          hscCode: r.hsc_code,
          revenue: r.revenue,
          count: parseInt(r.count, 10),
        })),
        pendingPipeline: {
          value: pipeline.pipeline_value,
          count: parseInt(pipeline.pipeline_count, 10),
        },
      };
    },

    async computeRejectionMetrics(
      providerId: string,
      periodStart: string,
      periodEnd: string,
      filters?: DashboardQueryFilters,
    ): Promise<RejectionMetrics> {
      const claimTypeCondition = buildClaimTypeCondition(filters?.claimType);

      // Totals for rejection rate denominator: assessed + rejected + adjusted
      const totalsResult = await db.execute<{
        total_assessed: string;
        total_rejected: string;
        total_adjusted: string;
      }>(sql`
        SELECT
          COUNT(*) FILTER (WHERE c.state = 'ASSESSED' OR c.state = 'PAID') AS total_assessed,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED') AS total_rejected,
          COUNT(*) FILTER (WHERE c.state = 'ADJUSTED') AS total_adjusted
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED')
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      const totals = totalsResult.rows[0] ?? { total_assessed: '0', total_rejected: '0', total_adjusted: '0' };
      const assessed = parseInt(totals.total_assessed, 10);
      const rejected = parseInt(totals.total_rejected, 10);
      const adjusted = parseInt(totals.total_adjusted, 10);
      const denominator = assessed + rejected + adjusted;
      const rate = denominator > 0
        ? ((rejected / denominator) * 100).toFixed(2)
        : '0.00';

      // By explanatory code
      const byCodeResult = await db.execute<{
        code: string;
        count: string;
      }>(sql`
        SELECT
          code_entry::TEXT AS code,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id,
        LATERAL jsonb_array_elements_text(acd.assessment_explanatory_codes) AS code_entry
        WHERE c.physician_id = ${providerId}
          AND c.state = 'REJECTED'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          AND acd.assessment_explanatory_codes IS NOT NULL
          ${claimTypeCondition}
        GROUP BY code_entry
        ORDER BY COUNT(*) DESC
      `);

      // By HSC code
      const byHscResult = await db.execute<{
        hsc_code: string;
        total: string;
        rejected_count: string;
      }>(sql`
        SELECT
          acd.health_service_code AS hsc_code,
          COUNT(*)::TEXT AS total,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS rejected_count
        FROM claims c
        JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED')
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
        GROUP BY acd.health_service_code
        HAVING COUNT(*) FILTER (WHERE c.state = 'REJECTED') > 0
        ORDER BY COUNT(*) FILTER (WHERE c.state = 'REJECTED') DESC
      `);

      // Resolution funnel: rejected -> resubmitted -> paid_on_resubmission -> written_off
      // Resubmitted = claims that were previously rejected, now in QUEUED/SUBMITTED/ASSESSED/PAID state
      // For simplicity, we use audit history counts. Here we approximate with current states.
      const funnelResult = await db.execute<{
        rejected: string;
        written_off: string;
      }>(sql`
        SELECT
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS rejected,
          COUNT(*) FILTER (WHERE c.state = 'WRITTEN_OFF')::TEXT AS written_off
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      const funnel = funnelResult.rows[0] ?? { rejected: '0', written_off: '0' };

      return {
        totalAssessed: assessed,
        totalRejected: rejected,
        totalAdjusted: adjusted,
        rejectionRate: rate,
        byExplanatoryCode: byCodeResult.rows.map((r) => ({
          code: r.code,
          count: parseInt(r.count, 10),
        })),
        byHscCode: byHscResult.rows.map((r) => {
          const total = parseInt(r.total, 10);
          const rejCount = parseInt(r.rejected_count, 10);
          return {
            hscCode: r.hsc_code,
            count: rejCount,
            rate: total > 0 ? ((rejCount / total) * 100).toFixed(2) : '0.00',
          };
        }),
        resolutionFunnel: {
          rejected: parseInt(funnel.rejected, 10),
          resubmitted: 0, // Requires audit trail cross-reference
          paidOnResubmission: 0,
          writtenOff: parseInt(funnel.written_off, 10),
        },
      };
    },

    async computeAgingMetrics(
      providerId: string,
      filters?: DashboardQueryFilters,
    ): Promise<AgingMetrics> {
      const claimTypeCondition = buildClaimTypeCondition(filters?.claimType);

      // Unresolved claims by aging bracket from DOS
      const agingResult = await db.execute<{
        bracket_label: string;
        min_days: string;
        max_days: string | null;
        count: string;
        total_value: string;
      }>(sql`
        SELECT
          CASE
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 0 AND 30 THEN '0-30 days'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 31 AND 60 THEN '31-60 days'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 61 AND 90 THEN '61-90 days'
            ELSE '90+ days'
          END AS bracket_label,
          CASE
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 0 AND 30 THEN '0'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 31 AND 60 THEN '31'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 61 AND 90 THEN '61'
            ELSE '91'
          END AS min_days,
          CASE
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 0 AND 30 THEN '30'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 31 AND 60 THEN '60'
            WHEN (CURRENT_DATE - c.date_of_service) BETWEEN 61 AND 90 THEN '90'
            ELSE NULL
          END AS max_days,
          COUNT(*)::TEXT AS count,
          COALESCE(SUM(CAST(acd.submitted_fee AS NUMERIC)), 0)::TEXT AS total_value
        FROM claims c
        LEFT JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('DRAFT', 'VALIDATED', 'QUEUED', 'SUBMITTED')
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
        GROUP BY bracket_label, min_days, max_days
        ORDER BY min_days
      `);

      // Approaching deadline (within 7 days)
      const deadlineResult = await db.execute<{
        claim_id: string;
        deadline: string;
        days_remaining: string;
      }>(sql`
        SELECT
          c.claim_id,
          c.submission_deadline AS deadline,
          (c.submission_deadline::DATE - CURRENT_DATE)::TEXT AS days_remaining
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('DRAFT', 'VALIDATED', 'QUEUED')
          AND c.submission_deadline IS NOT NULL
          AND (c.submission_deadline::DATE - CURRENT_DATE) BETWEEN 0 AND 7
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
        ORDER BY c.submission_deadline
      `);

      // Expired claims
      const expiredResult = await db.execute<{
        count: string;
      }>(sql`
        SELECT COUNT(*)::TEXT AS count
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.state = 'EXPIRED'
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      // Average resolution time (DOS to PAID)
      const avgResResult = await db.execute<{
        avg_days: string | null;
      }>(sql`
        SELECT
          AVG(c.updated_at::DATE - c.date_of_service)::TEXT AS avg_days
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.state = 'PAID'
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      // Stale claims (DRAFT or VALIDATED >14 days old)
      const staleResult = await db.execute<{
        count: string;
      }>(sql`
        SELECT COUNT(*)::TEXT AS count
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.state IN ('DRAFT', 'VALIDATED')
          AND c.created_at < (CURRENT_TIMESTAMP - INTERVAL '14 days')
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      return {
        brackets: agingResult.rows.map((r) => ({
          label: r.bracket_label,
          minDays: parseInt(r.min_days, 10),
          maxDays: r.max_days ? parseInt(r.max_days, 10) : null,
          count: parseInt(r.count, 10),
          value: r.total_value,
        })),
        approachingDeadline: {
          count: deadlineResult.rows.length,
          claims: deadlineResult.rows.map((r) => ({
            claimId: r.claim_id,
            deadline: r.deadline,
            daysRemaining: parseInt(r.days_remaining, 10),
          })),
        },
        expiredClaims: {
          count: parseInt(expiredResult.rows[0]?.count ?? '0', 10),
        },
        avgResolutionDays: avgResResult.rows[0]?.avg_days
          ? Math.round(parseFloat(avgResResult.rows[0].avg_days))
          : null,
        staleClaims: {
          count: parseInt(staleResult.rows[0]?.count ?? '0', 10),
        },
      };
    },

    async computeWcbMetrics(
      providerId: string,
      periodStart: string,
      periodEnd: string,
      filters?: DashboardQueryFilters,
    ): Promise<WcbMetrics> {
      // By form type
      const formTypeResult = await db.execute<{
        form_id: string;
        count: string;
        revenue: string;
      }>(sql`
        SELECT
          wcd.form_id,
          COUNT(*)::TEXT AS count,
          COALESCE(SUM(il.total_amount), 0)::TEXT AS revenue
        FROM claims c
        JOIN wcb_claim_details wcd ON wcd.claim_id = c.claim_id
        LEFT JOIN LATERAL (
          SELECT COALESCE(SUM(CAST(wil.amount AS NUMERIC)), 0) AS total_amount
          FROM wcb_invoice_lines wil
          WHERE wil.wcb_claim_detail_id = wcd.wcb_claim_detail_id
        ) il ON TRUE
        WHERE c.physician_id = ${providerId}
          AND c.claim_type = 'WCB'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
        GROUP BY wcd.form_id
        ORDER BY COUNT(*) DESC
      `);

      // Timing tier distribution from validation_result JSONB
      const tierResult = await db.execute<{
        tier: string;
        count: string;
      }>(sql`
        SELECT
          c.validation_result->>'timing_tier' AS tier,
          COUNT(*)::TEXT AS count
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.claim_type = 'WCB'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.validation_result->>'timing_tier' IS NOT NULL
          AND c.deleted_at IS NULL
        GROUP BY c.validation_result->>'timing_tier'
        ORDER BY count DESC
      `);

      // Fee per timing tier
      const feeTierResult = await db.execute<{
        tier: string;
        total_fee: string;
        avg_fee: string;
        count: string;
      }>(sql`
        SELECT
          c.validation_result->>'timing_tier' AS tier,
          COALESCE(SUM(il.total_amount), 0)::TEXT AS total_fee,
          CASE WHEN COUNT(*) > 0
            THEN (COALESCE(SUM(il.total_amount), 0) / COUNT(*))::TEXT
            ELSE '0'
          END AS avg_fee,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN wcb_claim_details wcd ON wcd.claim_id = c.claim_id
        LEFT JOIN LATERAL (
          SELECT COALESCE(SUM(CAST(wil.amount AS NUMERIC)), 0) AS total_amount
          FROM wcb_invoice_lines wil
          WHERE wil.wcb_claim_detail_id = wcd.wcb_claim_detail_id
        ) il ON TRUE
        WHERE c.physician_id = ${providerId}
          AND c.claim_type = 'WCB'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.validation_result->>'timing_tier' IS NOT NULL
          AND c.deleted_at IS NULL
        GROUP BY c.validation_result->>'timing_tier'
        ORDER BY tier
      `);

      // WCB revenue trend (monthly)
      const trendResult = await db.execute<{
        month: string;
        revenue: string;
        count: string;
      }>(sql`
        SELECT
          TO_CHAR(c.date_of_service, 'YYYY-MM') AS month,
          COALESCE(SUM(il.total_amount), 0)::TEXT AS revenue,
          COUNT(*)::TEXT AS count
        FROM claims c
        JOIN wcb_claim_details wcd ON wcd.claim_id = c.claim_id
        LEFT JOIN LATERAL (
          SELECT COALESCE(SUM(CAST(wil.amount AS NUMERIC)), 0) AS total_amount
          FROM wcb_invoice_lines wil
          WHERE wil.wcb_claim_detail_id = wcd.wcb_claim_detail_id
        ) il ON TRUE
        WHERE c.physician_id = ${providerId}
          AND c.claim_type = 'WCB'
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
        GROUP BY TO_CHAR(c.date_of_service, 'YYYY-MM')
        ORDER BY month
      `);

      // WCB rejection rate
      const rejResult = await db.execute<{
        total_claims: string;
        total_rejected: string;
      }>(sql`
        SELECT
          COUNT(*)::TEXT AS total_claims,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS total_rejected
        FROM claims c
        WHERE c.physician_id = ${providerId}
          AND c.claim_type = 'WCB'
          AND c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED')
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
      `);

      const rejTotals = rejResult.rows[0] ?? { total_claims: '0', total_rejected: '0' };
      const totalClaims = parseInt(rejTotals.total_claims, 10);
      const totalRejected = parseInt(rejTotals.total_rejected, 10);

      return {
        byFormType: formTypeResult.rows.map((r) => ({
          formId: r.form_id,
          count: parseInt(r.count, 10),
          revenue: r.revenue,
        })),
        timingTierDistribution: tierResult.rows.map((r) => ({
          tier: r.tier,
          count: parseInt(r.count, 10),
        })),
        feeByTimingTier: feeTierResult.rows.map((r) => ({
          tier: r.tier,
          totalFee: r.total_fee,
          avgFee: r.avg_fee,
          count: parseInt(r.count, 10),
        })),
        revenueTrend: trendResult.rows.map((r) => ({
          month: r.month,
          revenue: r.revenue,
          count: parseInt(r.count, 10),
        })),
        rejectionRate: totalClaims > 0
          ? ((totalRejected / totalClaims) * 100).toFixed(2)
          : '0.00',
        totalClaims,
        totalRejected,
      };
    },

    async computeAiCoachMetrics(
      providerId: string,
      periodStart: string,
      periodEnd: string,
    ): Promise<AiCoachMetrics> {
      // Overall acceptance rate from suggestion events
      const overallResult = await db.execute<{
        total_generated: string;
        total_accepted: string;
        total_dismissed: string;
        revenue_recovered: string;
      }>(sql`
        SELECT
          COUNT(*) FILTER (WHERE event_type = 'generated')::TEXT AS total_generated,
          COUNT(*) FILTER (WHERE event_type = 'accepted')::TEXT AS total_accepted,
          COUNT(*) FILTER (WHERE event_type = 'dismissed')::TEXT AS total_dismissed,
          COALESCE(SUM(CAST(revenue_impact AS NUMERIC)) FILTER (WHERE event_type = 'accepted'), 0)::TEXT AS revenue_recovered
        FROM ai_suggestion_events
        WHERE provider_id = ${providerId}
          AND created_at BETWEEN ${periodStart}::TIMESTAMPTZ AND (${periodEnd}::DATE + INTERVAL '1 day')::TIMESTAMPTZ
      `);

      const overall = overallResult.rows[0] ?? {
        total_generated: '0',
        total_accepted: '0',
        total_dismissed: '0',
        revenue_recovered: '0',
      };

      const totalGen = parseInt(overall.total_generated, 10);
      const totalAcc = parseInt(overall.total_accepted, 10);
      const totalDis = parseInt(overall.total_dismissed, 10);

      // By category
      const categoryResult = await db.execute<{
        category: string;
        generated: string;
        accepted: string;
        revenue: string;
      }>(sql`
        SELECT
          category,
          COUNT(*) FILTER (WHERE event_type = 'generated')::TEXT AS generated,
          COUNT(*) FILTER (WHERE event_type = 'accepted')::TEXT AS accepted,
          COALESCE(SUM(CAST(revenue_impact AS NUMERIC)) FILTER (WHERE event_type = 'accepted'), 0)::TEXT AS revenue
        FROM ai_suggestion_events
        WHERE provider_id = ${providerId}
          AND created_at BETWEEN ${periodStart}::TIMESTAMPTZ AND (${periodEnd}::DATE + INTERVAL '1 day')::TIMESTAMPTZ
        GROUP BY category
        ORDER BY COUNT(*) FILTER (WHERE event_type = 'accepted') DESC
      `);

      // Top accepted rules
      const topRulesResult = await db.execute<{
        rule_id: string;
        rule_name: string;
        accepted_count: string;
        revenue: string;
      }>(sql`
        SELECT
          ase.rule_id,
          COALESCE(ar.name, 'Unknown Rule') AS rule_name,
          COUNT(*)::TEXT AS accepted_count,
          COALESCE(SUM(CAST(ase.revenue_impact AS NUMERIC)), 0)::TEXT AS revenue
        FROM ai_suggestion_events ase
        LEFT JOIN ai_rules ar ON ar.rule_id = ase.rule_id
        WHERE ase.provider_id = ${providerId}
          AND ase.event_type = 'accepted'
          AND ase.created_at BETWEEN ${periodStart}::TIMESTAMPTZ AND (${periodEnd}::DATE + INTERVAL '1 day')::TIMESTAMPTZ
        GROUP BY ase.rule_id, ar.name
        ORDER BY COUNT(*) DESC
        LIMIT 5
      `);

      // Suppressed rules
      const suppressedResult = await db.execute<{
        rule_id: string;
        rule_name: string;
      }>(sql`
        SELECT
          apl.rule_id,
          COALESCE(ar.name, 'Unknown Rule') AS rule_name
        FROM ai_provider_learning apl
        LEFT JOIN ai_rules ar ON ar.rule_id = apl.rule_id
        WHERE apl.provider_id = ${providerId}
          AND apl.is_suppressed = TRUE
      `);

      return {
        acceptanceRate: totalGen > 0
          ? ((totalAcc / totalGen) * 100).toFixed(2)
          : '0.00',
        totalGenerated: totalGen,
        totalAccepted: totalAcc,
        totalDismissed: totalDis,
        revenueRecovered: overall.revenue_recovered,
        byCategory: categoryResult.rows.map((r) => {
          const gen = parseInt(r.generated, 10);
          const acc = parseInt(r.accepted, 10);
          return {
            category: r.category,
            generated: gen,
            accepted: acc,
            rate: gen > 0 ? ((acc / gen) * 100).toFixed(2) : '0.00',
            revenue: r.revenue,
          };
        }),
        topAcceptedRules: topRulesResult.rows.map((r) => ({
          ruleId: r.rule_id,
          ruleName: r.rule_name,
          acceptedCount: parseInt(r.accepted_count, 10),
          revenue: r.revenue,
        })),
        suppressedRules: suppressedResult.rows.map((r) => ({
          ruleId: r.rule_id,
          ruleName: r.rule_name,
        })),
      };
    },

    async computeMultiSiteMetrics(
      providerId: string,
      periodStart: string,
      periodEnd: string,
      locationIds?: string[],
    ): Promise<MultiSiteMetrics> {
      const locationFilter = locationIds && locationIds.length > 0
        ? sql`AND pl.location_id = ANY(${locationIds})`
        : sql``;

      const result = await db.execute<{
        location_id: string;
        location_name: string;
        revenue: string;
        claim_count: string;
        total_decided: string;
        rejected_count: string;
        rrnp_premium: string;
      }>(sql`
        SELECT
          pl.location_id,
          pl.name AS location_name,
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)) FILTER (WHERE c.state = 'PAID'), 0)::TEXT AS revenue,
          COUNT(*)::TEXT AS claim_count,
          COUNT(*) FILTER (WHERE c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED'))::TEXT AS total_decided,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS rejected_count,
          COALESCE(pl.rrnp_rate, 0)::TEXT AS rrnp_premium
        FROM practice_locations pl
        LEFT JOIN ahcip_claim_details acd ON acd.functional_centre = pl.functional_centre
        LEFT JOIN claims c ON c.claim_id = acd.claim_id
          AND c.physician_id = ${providerId}
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
        WHERE pl.provider_id = ${providerId}
          AND pl.is_active = TRUE
          ${locationFilter}
        GROUP BY pl.location_id, pl.name, pl.rrnp_rate
        ORDER BY revenue DESC
      `);

      return {
        locations: result.rows.map((r) => {
          const decided = parseInt(r.total_decided, 10);
          const rejCount = parseInt(r.rejected_count, 10);
          return {
            locationId: r.location_id,
            locationName: r.location_name,
            revenue: r.revenue,
            claimCount: parseInt(r.claim_count, 10),
            rejectionRate: decided > 0
              ? ((rejCount / decided) * 100).toFixed(2)
              : '0.00',
            rrnpPremium: r.rrnp_premium,
          };
        }),
      };
    },

    async computeKpis(
      providerId: string,
      periodStart: string,
      periodEnd: string,
      priorPeriodStart: string,
      priorPeriodEnd: string,
      filters?: DashboardQueryFilters,
    ): Promise<KpiMetrics> {
      const claimTypeCondition = buildClaimTypeCondition(filters?.claimType);

      // Current period KPIs
      const currentResult = await db.execute<{
        revenue: string;
        claims_submitted: string;
        total_decided: string;
        rejected: string;
        avg_fee: string;
        pending: string;
      }>(sql`
        SELECT
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)) FILTER (WHERE c.state = 'PAID'), 0)::TEXT AS revenue,
          COUNT(*) FILTER (WHERE c.state IN ('SUBMITTED', 'ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED'))::TEXT AS claims_submitted,
          COUNT(*) FILTER (WHERE c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED'))::TEXT AS total_decided,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS rejected,
          CASE WHEN COUNT(*) FILTER (WHERE c.state = 'PAID') > 0
            THEN (COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)) FILTER (WHERE c.state = 'PAID'), 0) /
                  COUNT(*) FILTER (WHERE c.state = 'PAID'))::TEXT
            ELSE '0.00'
          END AS avg_fee,
          COALESCE(SUM(CAST(acd.submitted_fee AS NUMERIC)) FILTER (WHERE c.state IN ('QUEUED', 'SUBMITTED')), 0)::TEXT AS pending
        FROM claims c
        LEFT JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.date_of_service BETWEEN ${periodStart} AND ${periodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      // Prior period KPIs
      const priorResult = await db.execute<{
        revenue: string;
        claims_submitted: string;
        total_decided: string;
        rejected: string;
        avg_fee: string;
        pending: string;
      }>(sql`
        SELECT
          COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)) FILTER (WHERE c.state = 'PAID'), 0)::TEXT AS revenue,
          COUNT(*) FILTER (WHERE c.state IN ('SUBMITTED', 'ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED'))::TEXT AS claims_submitted,
          COUNT(*) FILTER (WHERE c.state IN ('ASSESSED', 'PAID', 'REJECTED', 'ADJUSTED'))::TEXT AS total_decided,
          COUNT(*) FILTER (WHERE c.state = 'REJECTED')::TEXT AS rejected,
          CASE WHEN COUNT(*) FILTER (WHERE c.state = 'PAID') > 0
            THEN (COALESCE(SUM(CAST(acd.assessed_fee AS NUMERIC)) FILTER (WHERE c.state = 'PAID'), 0) /
                  COUNT(*) FILTER (WHERE c.state = 'PAID'))::TEXT
            ELSE '0.00'
          END AS avg_fee,
          COALESCE(SUM(CAST(acd.submitted_fee AS NUMERIC)) FILTER (WHERE c.state IN ('QUEUED', 'SUBMITTED')), 0)::TEXT AS pending
        FROM claims c
        LEFT JOIN ahcip_claim_details acd ON acd.claim_id = c.claim_id
        WHERE c.physician_id = ${providerId}
          AND c.date_of_service BETWEEN ${priorPeriodStart} AND ${priorPeriodEnd}
          AND c.deleted_at IS NULL
          ${claimTypeCondition}
      `);

      const current = currentResult.rows[0] ?? {
        revenue: '0', claims_submitted: '0', total_decided: '0',
        rejected: '0', avg_fee: '0.00', pending: '0',
      };
      const prior = priorResult.rows[0] ?? {
        revenue: '0', claims_submitted: '0', total_decided: '0',
        rejected: '0', avg_fee: '0.00', pending: '0',
      };

      const curRevenue = parseFloat(current.revenue);
      const priRevenue = parseFloat(prior.revenue);
      const curSubmitted = parseInt(current.claims_submitted, 10);
      const priSubmitted = parseInt(prior.claims_submitted, 10);
      const curDecided = parseInt(current.total_decided, 10);
      const curRej = parseInt(current.rejected, 10);
      const priDecided = parseInt(prior.total_decided, 10);
      const priRej = parseInt(prior.rejected, 10);
      const curAvgFee = parseFloat(current.avg_fee);
      const priAvgFee = parseFloat(prior.avg_fee);
      const curPending = parseFloat(current.pending);
      const priPending = parseFloat(prior.pending);

      const curRejRate = curDecided > 0 ? (curRej / curDecided) * 100 : 0;
      const priRejRate = priDecided > 0 ? (priRej / priDecided) * 100 : 0;

      return {
        totalRevenue: curRevenue.toFixed(2),
        priorRevenue: priRevenue.toFixed(2),
        revenueDelta: computeDelta(curRevenue, priRevenue),
        claimsSubmitted: curSubmitted,
        priorClaimsSubmitted: priSubmitted,
        claimsDelta: computeDelta(curSubmitted, priSubmitted),
        rejectionRate: curRejRate.toFixed(2),
        priorRejectionRate: priRejRate.toFixed(2),
        rejectionDelta: computeDelta(curRejRate, priRejRate),
        avgFeePerClaim: curAvgFee.toFixed(2),
        priorAvgFee: priAvgFee.toFixed(2),
        avgFeeDelta: computeDelta(curAvgFee, priAvgFee),
        pendingPipeline: curPending.toFixed(2),
        priorPendingPipeline: priPending.toFixed(2),
        pipelineDelta: computeDelta(curPending, priPending),
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildClaimTypeCondition(claimType?: 'AHCIP' | 'WCB' | 'BOTH') {
  if (!claimType || claimType === 'BOTH') {
    return sql``;
  }
  return sql`AND c.claim_type = ${claimType}`;
}

function computeDelta(current: number, prior: number): string {
  if (prior === 0) {
    return current > 0 ? '100.00' : '0.00';
  }
  return (((current - prior) / Math.abs(prior)) * 100).toFixed(2);
}

export type DashboardQueryRepository = ReturnType<
  typeof createDashboardQueryRepository
>;
