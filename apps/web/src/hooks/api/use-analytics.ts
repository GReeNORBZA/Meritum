'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { ApiResponse, PaginatedResponse } from '@/lib/api/client';

// ---------- Types ----------

export type AnalyticsPeriod =
  | 'this_week'
  | 'this_month'
  | 'this_quarter'
  | 'this_year'
  | 'custom';

export interface RevenueDataPoint {
  date: string;
  revenue: number;
  claims_count: number;
}

export interface HscCodeRevenue {
  code: string;
  description: string;
  revenue: number;
  claims_count: number;
}

export interface RevenueAnalytics {
  total_revenue: number;
  average_per_claim: number;
  top_code_revenue: number;
  top_code: string;
  trend: RevenueDataPoint[];
  top_codes: HscCodeRevenue[];
  period: string;
}

export interface RejectionDataPoint {
  date: string;
  rejections: number;
  total_claims: number;
  rate: number;
}

export interface RejectionCode {
  code: string;
  description: string;
  count: number;
  percentage: number;
}

export interface RejectionAnalytics {
  rejection_rate: number;
  total_rejections: number;
  resubmission_success_rate: number;
  trend: RejectionDataPoint[];
  top_codes: RejectionCode[];
  period: string;
}

export interface AgingBracket {
  bracket: string;
  count: number;
  amount: number;
}

export interface AgingClaim {
  id: string;
  claim_number: string;
  patient_name: string;
  date_of_service: string;
  age_days: number;
  amount: number;
  deadline_date: string;
}

export interface AgingAnalytics {
  brackets: AgingBracket[];
  approaching_deadline: AgingClaim[];
  total_outstanding: number;
  period: string;
}

export interface WcbFormType {
  form_type: string;
  count: number;
  percentage: number;
}

export interface WcbTimingTier {
  tier: string;
  count: number;
  percentage: number;
}

export interface WcbFormRevenue {
  form_type: string;
  revenue: number;
  claims_count: number;
}

export interface WcbAnalytics {
  claims_by_form_type: WcbFormType[];
  timing_tiers: WcbTimingTier[];
  revenue_by_form_type: WcbFormRevenue[];
  total_claims: number;
  total_revenue: number;
  period: string;
}

export interface AiCoachDataPoint {
  date: string;
  acceptance_rate: number;
  suggestions_count: number;
}

export interface RuleTypeMetric {
  rule_type: string;
  accepted: number;
  rejected: number;
  total: number;
  acceptance_rate: number;
}

export interface AiCoachAnalytics {
  acceptance_rate: number;
  total_suggestions: number;
  revenue_recovered: number;
  trend: AiCoachDataPoint[];
  rule_types: RuleTypeMetric[];
  period: string;
}

export interface SiteMetric {
  location_id: string;
  location_name: string;
  revenue: number;
  claims_count: number;
  rejection_rate: number;
}

export interface MultiSiteAnalytics {
  sites: SiteMetric[];
  total_revenue: number;
  total_claims: number;
  period: string;
}

export interface Report {
  id: string;
  name: string;
  report_type: string;
  status: 'PENDING' | 'GENERATING' | 'COMPLETED' | 'FAILED';
  download_url?: string;
  created_at: string;
  completed_at?: string;
}

export interface ReportFilters {
  page?: number;
  pageSize?: number;
  report_type?: string;
  status?: string;
}

export interface GenerateReportInput {
  report_type: string;
  period?: string;
  date_from?: string;
  date_to?: string;
  format?: 'pdf' | 'csv' | 'xlsx';
}

export interface ReportSubscription {
  id: string;
  report_type: string;
  frequency: 'daily' | 'weekly' | 'monthly';
  delivery_method: 'email' | 'download';
  is_active: boolean;
  last_sent_at?: string;
  next_send_at?: string;
  created_at: string;
}

export interface CreateSubscriptionInput {
  report_type: string;
  frequency: 'daily' | 'weekly' | 'monthly';
  delivery_method: 'email' | 'download';
}

export interface UpdateSubscriptionInput {
  is_active?: boolean;
  frequency?: 'daily' | 'weekly' | 'monthly';
  delivery_method?: 'email' | 'download';
}

// ---------- Analytics Queries ----------

export function useRevenueAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.revenue({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<RevenueAnalytics>>('/api/v1/analytics/revenue', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

export function useRejectionAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.rejections({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<RejectionAnalytics>>('/api/v1/analytics/rejections', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

export function useAgingAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.aging({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<AgingAnalytics>>('/api/v1/analytics/aging', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

export function useWcbAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.wcb({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<WcbAnalytics>>('/api/v1/analytics/wcb', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

export function useAiCoachAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.aiCoach({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<AiCoachAnalytics>>('/api/v1/analytics/ai-coach', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

export function useMultiSiteAnalytics(period: AnalyticsPeriod, dateFrom?: string, dateTo?: string) {
  return useQuery({
    queryKey: queryKeys.analytics.multiSite({ period, dateFrom, dateTo }),
    queryFn: () =>
      api.get<ApiResponse<MultiSiteAnalytics>>('/api/v1/analytics/multi-site', {
        params: { period, date_from: dateFrom, date_to: dateTo },
      }),
  });
}

// ---------- Reports Queries ----------

export function useReports(filters: ReportFilters = {}) {
  const { page = 1, pageSize = 20, report_type, status } = filters;

  return useQuery({
    queryKey: queryKeys.reports.list({ page, pageSize, report_type, status }),
    queryFn: () =>
      api.get<PaginatedResponse<Report>>('/api/v1/reports', {
        params: {
          page,
          page_size: pageSize,
          report_type,
          status,
        },
      }),
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: GenerateReportInput) =>
      api.post<ApiResponse<Report>>('/api/v1/reports/accountant', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.all });
    },
  });
}

// ---------- Report Subscriptions ----------

export function useReportSubscriptions() {
  return useQuery({
    queryKey: queryKeys.reports.subscriptions(),
    queryFn: () =>
      api.get<ApiResponse<ReportSubscription[]>>('/api/v1/report-subscriptions'),
  });
}

export function useCreateSubscription() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateSubscriptionInput) =>
      api.post<ApiResponse<ReportSubscription>>('/api/v1/report-subscriptions', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.subscriptions() });
    },
  });
}

export function useUpdateSubscription() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateSubscriptionInput }) =>
      api.put<ApiResponse<ReportSubscription>>(`/api/v1/report-subscriptions/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.subscriptions() });
    },
  });
}

export function useDeleteSubscription() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/report-subscriptions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.subscriptions() });
    },
  });
}
