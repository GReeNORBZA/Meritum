// ============================================================================
// Domain 8: Analytics & Reporting — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  TimePeriod,
  AnalyticsClaimTypeFilter,
  ReportType,
  ReportFrequency,
  DeliveryMethod,
} from '../../constants/analytics.constants.js';

// --- Enum Value Arrays ---

const TIME_PERIODS = [
  TimePeriod.THIS_WEEK,
  TimePeriod.THIS_MONTH,
  TimePeriod.LAST_MONTH,
  TimePeriod.THIS_QUARTER,
  TimePeriod.THIS_YEAR,
  TimePeriod.CUSTOM_RANGE,
  TimePeriod.TRAILING_12_MONTHS,
] as const;

const CLAIM_TYPE_FILTERS = [
  AnalyticsClaimTypeFilter.AHCIP,
  AnalyticsClaimTypeFilter.WCB,
  AnalyticsClaimTypeFilter.BOTH,
] as const;

const REPORT_TYPES = [
  ReportType.ACCOUNTANT_SUMMARY,
  ReportType.ACCOUNTANT_DETAIL,
  ReportType.WEEKLY_SUMMARY,
  ReportType.MONTHLY_PERFORMANCE,
  ReportType.RRNP_QUARTERLY,
  ReportType.WCB_TIMING,
  ReportType.REJECTION_DIGEST,
  ReportType.DATA_PORTABILITY,
] as const;

const FREQUENCIES = [
  ReportFrequency.DAILY,
  ReportFrequency.WEEKLY,
  ReportFrequency.MONTHLY,
  ReportFrequency.QUARTERLY,
] as const;

const DELIVERY_METHODS = [
  DeliveryMethod.IN_APP,
  DeliveryMethod.EMAIL,
  DeliveryMethod.BOTH,
] as const;

// Subscribable report types (exclude one-off types like DATA_PORTABILITY)
const SUBSCRIBABLE_REPORT_TYPES = [
  ReportType.WEEKLY_SUMMARY,
  ReportType.MONTHLY_PERFORMANCE,
  ReportType.RRNP_QUARTERLY,
  ReportType.WCB_TIMING,
  ReportType.REJECTION_DIGEST,
] as const;

const ACCOUNTANT_FORMATS = ['csv', 'pdf_summary', 'pdf_detail'] as const;

// --- Helpers ---

const isoDateString = z.string().regex(
  /^\d{4}-\d{2}-\d{2}$/,
  'Must be an ISO 8601 date (YYYY-MM-DD)',
);

// Max date range: 2 years (730 days)
const MAX_RANGE_DAYS = 730;

function validateDateRange(
  startDate: string | undefined,
  endDate: string | undefined,
): boolean {
  if (!startDate || !endDate) return true;
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) return true; // let regex handle format
  const diffMs = end.getTime() - start.getTime();
  const diffDays = diffMs / (1000 * 60 * 60 * 24);
  return diffDays >= 0 && diffDays <= MAX_RANGE_DAYS;
}

// ============================================================================
// Dashboard Query Params
// ============================================================================

// --- Period Params ---
// start_date/end_date required when period is CUSTOM_RANGE

export const periodParamsSchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type PeriodParams = z.infer<typeof periodParamsSchema>;

// --- Dashboard Filter ---

export const dashboardFilterSchema = z.object({
  claim_type: z.enum(CLAIM_TYPE_FILTERS).optional(),
  ba_number: z.string().max(20).optional(),
  location_id: z.string().uuid().optional(),
  claim_state: z.array(z.string().max(30)).optional(),
  hsc_code: z.string().max(10).optional(),
});

export type DashboardFilter = z.infer<typeof dashboardFilterSchema>;

// --- Revenue Query ---

export const revenueQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
    claim_type: z.enum(CLAIM_TYPE_FILTERS).optional(),
    ba_number: z.string().max(20).optional(),
    location_id: z.string().uuid().optional(),
    claim_state: z.array(z.string().max(30)).optional(),
    hsc_code: z.string().max(10).optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type RevenueQuery = z.infer<typeof revenueQuerySchema>;

// --- Rejection Query ---

export const rejectionQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
    claim_type: z.enum(CLAIM_TYPE_FILTERS).optional(),
    hsc_code: z.string().max(10).optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type RejectionQuery = z.infer<typeof rejectionQuerySchema>;

// --- Aging Query ---

export const agingQuerySchema = z.object({
  claim_type: z.enum(CLAIM_TYPE_FILTERS).optional(),
});

export type AgingQuery = z.infer<typeof agingQuerySchema>;

// --- WCB Query ---

export const wcbQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
    form_type: z.string().max(30).optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type WcbQuery = z.infer<typeof wcbQuerySchema>;

// --- AI Coach Query ---

export const aiCoachQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type AiCoachQuery = z.infer<typeof aiCoachQuerySchema>;

// --- Multi-Site Query ---

export const multiSiteQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
    compare_locations: z
      .array(z.string().uuid())
      .max(2, 'Maximum 2 locations for side-by-side comparison')
      .optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type MultiSiteQuery = z.infer<typeof multiSiteQuerySchema>;

// --- KPI Query ---

export const kpiQuerySchema = z
  .object({
    period: z.enum(TIME_PERIODS),
    start_date: isoDateString.optional(),
    end_date: isoDateString.optional(),
    claim_type: z.enum(CLAIM_TYPE_FILTERS).optional(),
    ba_number: z.string().max(20).optional(),
    location_id: z.string().uuid().optional(),
    claim_state: z.array(z.string().max(30)).optional(),
    hsc_code: z.string().max(10).optional(),
  })
  .refine(
    (data) => {
      if (data.period === TimePeriod.CUSTOM_RANGE) {
        return !!data.start_date && !!data.end_date;
      }
      return true;
    },
    {
      message:
        'start_date and end_date are required when period is CUSTOM_RANGE',
      path: ['start_date'],
    },
  )
  .refine(
    (data) => validateDateRange(data.start_date, data.end_date),
    {
      message:
        'end_date must be >= start_date and range must not exceed 2 years',
      path: ['end_date'],
    },
  );

export type KpiQuery = z.infer<typeof kpiQuerySchema>;

// ============================================================================
// Report Generation
// ============================================================================

// --- Accountant Report ---

export const accountantReportSchema = z
  .object({
    period_start: isoDateString,
    period_end: isoDateString,
    format: z.enum(ACCOUNTANT_FORMATS),
  })
  .refine(
    (data) => validateDateRange(data.period_start, data.period_end),
    {
      message:
        'period_end must be >= period_start and range must not exceed 2 years',
      path: ['period_end'],
    },
  );

export type AccountantReport = z.infer<typeof accountantReportSchema>;

// --- Data Portability ---

export const dataPortabilitySchema = z.object({
  password: z
    .string()
    .min(12, 'Encryption password must be at least 12 characters')
    .optional(),
});

export type DataPortability = z.infer<typeof dataPortabilitySchema>;

// --- Report ID Param ---

export const reportIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ReportIdParam = z.infer<typeof reportIdParamSchema>;

// --- Report List Query ---

export const reportListQuerySchema = z.object({
  report_type: z.enum(REPORT_TYPES).optional(),
  start_date: isoDateString.optional(),
  end_date: isoDateString.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

export type ReportListQuery = z.infer<typeof reportListQuerySchema>;

// ============================================================================
// Subscriptions
// ============================================================================

// --- Create Subscription ---

export const createSubscriptionSchema = z.object({
  report_type: z.enum(SUBSCRIBABLE_REPORT_TYPES),
  frequency: z.enum(FREQUENCIES),
  delivery_method: z.enum(DELIVERY_METHODS).default(DeliveryMethod.IN_APP),
});

export type CreateSubscription = z.infer<typeof createSubscriptionSchema>;

// --- Update Subscription ---

export const updateSubscriptionSchema = z
  .object({
    frequency: z.enum(FREQUENCIES).optional(),
    delivery_method: z.enum(DELIVERY_METHODS).optional(),
    is_active: z.boolean().optional(),
  })
  .refine(
    (data) =>
      data.frequency !== undefined ||
      data.delivery_method !== undefined ||
      data.is_active !== undefined,
    { message: 'At least one field must be provided' },
  );

export type UpdateSubscription = z.infer<typeof updateSubscriptionSchema>;

// --- Subscription ID Param ---

export const subscriptionIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type SubscriptionIdParam = z.infer<typeof subscriptionIdParamSchema>;
