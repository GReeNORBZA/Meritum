// ============================================================================
// Domain 8: Analytics & Reporting — Constants
// ============================================================================

// --- Metric Keys (VARCHAR(50) identifiers for analytics_cache.metric_key) ---

export const MetricKey = {
  // Revenue metrics
  REVENUE_MONTHLY: 'revenue_monthly',
  REVENUE_BY_BA: 'revenue_by_ba',
  REVENUE_BY_LOCATION: 'revenue_by_location',
  REVENUE_BY_HSC: 'revenue_by_hsc',

  // Claim volume metrics
  CLAIMS_SUBMITTED: 'claims_submitted',
  CLAIMS_ASSESSED: 'claims_assessed',
  CLAIMS_PAID: 'claims_paid',
  CLAIMS_REJECTED: 'claims_rejected',
  CLAIMS_ADJUSTED: 'claims_adjusted',

  // Rejection metrics
  REJECTION_RATE_MONTHLY: 'rejection_rate_monthly',
  REJECTION_BY_CODE: 'rejection_by_code',
  REJECTION_BY_HSC: 'rejection_by_hsc',
  REJECTION_RESOLUTION_FUNNEL: 'rejection_resolution_funnel',

  // Aging & deadline metrics
  AGING_BRACKETS: 'aging_brackets',
  APPROACHING_DEADLINE: 'approaching_deadline',
  EXPIRED_CLAIMS: 'expired_claims',
  AVG_RESOLUTION_TIME: 'avg_resolution_time',
  STALE_CLAIMS: 'stale_claims',

  // WCB metrics
  WCB_BY_FORM_TYPE: 'wcb_by_form_type',
  WCB_TIMING_TIER_DIST: 'wcb_timing_tier_dist',
  WCB_FEE_TIER_ANALYSIS: 'wcb_fee_tier_analysis',
  WCB_REVENUE_TREND: 'wcb_revenue_trend',
  WCB_REJECTION_RATE: 'wcb_rejection_rate',

  // AI Coach metrics
  AI_COACH_ACCEPTANCE_RATE: 'ai_coach_acceptance_rate',
  AI_COACH_REVENUE_RECOVERED: 'ai_coach_revenue_recovered',
  AI_COACH_BY_CATEGORY: 'ai_coach_by_category',
  AI_COACH_TOP_ACCEPTED: 'ai_coach_top_accepted',
  AI_COACH_SUPPRESSED: 'ai_coach_suppressed',

  // Multi-site metrics
  MULTISITE_REVENUE: 'multisite_revenue',
  MULTISITE_CLAIMS: 'multisite_claims',
  MULTISITE_RRNP: 'multisite_rrnp',

  // Misc metrics
  PENDING_PIPELINE: 'pending_pipeline',
  AVG_FEE_PER_CLAIM: 'avg_fee_per_claim',
  TOP_HSC_CODES: 'top_hsc_codes',
} as const;

export type MetricKey = (typeof MetricKey)[keyof typeof MetricKey];

// --- Report Types (VARCHAR(50)) ---

export const ReportType = {
  ACCOUNTANT_SUMMARY: 'ACCOUNTANT_SUMMARY',
  ACCOUNTANT_DETAIL: 'ACCOUNTANT_DETAIL',
  WEEKLY_SUMMARY: 'WEEKLY_SUMMARY',
  MONTHLY_PERFORMANCE: 'MONTHLY_PERFORMANCE',
  RRNP_QUARTERLY: 'RRNP_QUARTERLY',
  WCB_TIMING: 'WCB_TIMING',
  REJECTION_DIGEST: 'REJECTION_DIGEST',
  DATA_PORTABILITY: 'DATA_PORTABILITY',
} as const;

export type ReportType = (typeof ReportType)[keyof typeof ReportType];

// --- Report Formats ---

export const ReportFormat = {
  PDF: 'PDF',
  CSV: 'CSV',
  ZIP: 'ZIP',
} as const;

export type ReportFormat = (typeof ReportFormat)[keyof typeof ReportFormat];

// --- Subscription Frequencies ---

export const ReportFrequency = {
  DAILY: 'DAILY',
  WEEKLY: 'WEEKLY',
  MONTHLY: 'MONTHLY',
  QUARTERLY: 'QUARTERLY',
} as const;

export type ReportFrequency =
  (typeof ReportFrequency)[keyof typeof ReportFrequency];

// --- Delivery Methods ---

export const DeliveryMethod = {
  IN_APP: 'IN_APP',
  EMAIL: 'EMAIL',
  BOTH: 'BOTH',
} as const;

export type DeliveryMethod =
  (typeof DeliveryMethod)[keyof typeof DeliveryMethod];

// --- Time Periods (dashboard period selector) ---

export const TimePeriod = {
  THIS_WEEK: 'THIS_WEEK',
  THIS_MONTH: 'THIS_MONTH',
  LAST_MONTH: 'LAST_MONTH',
  THIS_QUARTER: 'THIS_QUARTER',
  THIS_YEAR: 'THIS_YEAR',
  CUSTOM_RANGE: 'CUSTOM_RANGE',
  TRAILING_12_MONTHS: 'TRAILING_12_MONTHS',
} as const;

export type TimePeriod = (typeof TimePeriod)[keyof typeof TimePeriod];

// --- Period Comparison Mapping ---

interface PeriodComparisonConfig {
  readonly period: TimePeriod;
  readonly comparisonDescription: string;
}

export const PERIOD_COMPARISON_MAP: Readonly<
  Record<TimePeriod, PeriodComparisonConfig>
> = Object.freeze({
  [TimePeriod.THIS_WEEK]: {
    period: TimePeriod.THIS_WEEK,
    comparisonDescription: 'Same days last week',
  },
  [TimePeriod.THIS_MONTH]: {
    period: TimePeriod.THIS_MONTH,
    comparisonDescription: 'Same days prior month',
  },
  [TimePeriod.LAST_MONTH]: {
    period: TimePeriod.LAST_MONTH,
    comparisonDescription: 'Month before that',
  },
  [TimePeriod.THIS_QUARTER]: {
    period: TimePeriod.THIS_QUARTER,
    comparisonDescription: 'Same quarter prior year',
  },
  [TimePeriod.THIS_YEAR]: {
    period: TimePeriod.THIS_YEAR,
    comparisonDescription: 'Same period prior year',
  },
  [TimePeriod.CUSTOM_RANGE]: {
    period: TimePeriod.CUSTOM_RANGE,
    comparisonDescription: 'Same-length period immediately prior',
  },
  [TimePeriod.TRAILING_12_MONTHS]: {
    period: TimePeriod.TRAILING_12_MONTHS,
    comparisonDescription: '12 months before that',
  },
});

// --- Claim Type Filter ---

export const AnalyticsClaimTypeFilter = {
  AHCIP: 'AHCIP',
  WCB: 'WCB',
  BOTH: 'BOTH',
} as const;

export type AnalyticsClaimTypeFilter =
  (typeof AnalyticsClaimTypeFilter)[keyof typeof AnalyticsClaimTypeFilter];

// --- Aging Bracket Boundaries (days from date of service) ---

interface AgingBracketConfig {
  readonly label: string;
  readonly minDays: number;
  readonly maxDays: number | null;
}

export const AGING_BRACKET_CONFIGS: readonly AgingBracketConfig[] =
  Object.freeze([
    { label: '0-30 days', minDays: 0, maxDays: 30 },
    { label: '31-60 days', minDays: 31, maxDays: 60 },
    { label: '61-90 days', minDays: 61, maxDays: 90 },
    { label: '90+ days', minDays: 91, maxDays: null },
  ] as const);

// --- Analytics Audit Actions ---

export const AnalyticsAuditAction = {
  DASHBOARD_VIEWED: 'analytics.dashboard_viewed',
  REPORT_GENERATED: 'analytics.report_generated',
  REPORT_DOWNLOADED: 'analytics.report_downloaded',
  DATA_PORTABILITY_REQUESTED: 'analytics.data_portability_requested',
  DATA_PORTABILITY_DOWNLOADED: 'analytics.data_portability_downloaded',
  SUBSCRIPTION_CREATED: 'analytics.subscription_created',
  SUBSCRIPTION_UPDATED: 'analytics.subscription_updated',
  SUBSCRIPTION_CANCELLED: 'analytics.subscription_cancelled',
} as const;

export type AnalyticsAuditAction =
  (typeof AnalyticsAuditAction)[keyof typeof AnalyticsAuditAction];

// --- Report Retention Defaults (days) ---

export const REPORT_RETENTION_DAYS: Readonly<
  Record<'SCHEDULED' | 'ON_DEMAND' | 'DATA_PORTABILITY', number>
> = Object.freeze({
  SCHEDULED: 90,
  ON_DEMAND: 30,
  DATA_PORTABILITY: 3,
});

// --- Report Download Link Expiry (days) ---

export const REPORT_DOWNLOAD_EXPIRY_DAYS: Readonly<
  Record<'SCHEDULED' | 'ON_DEMAND' | 'DATA_PORTABILITY', number>
> = Object.freeze({
  SCHEDULED: 90,
  ON_DEMAND: 30,
  DATA_PORTABILITY: 3,
});
