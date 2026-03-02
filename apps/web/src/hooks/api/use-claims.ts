'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { PaginatedResponse, ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export interface ClaimLineItem {
  id: string;
  health_service_code: string;
  hsc_description?: string;
  modifiers: string[];
  diagnostic_codes: string[];
  calls: number;
  fee_amount: string;
  assessed_amount?: string | null;
}

export interface ClaimValidationResult {
  check_id: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  message: string;
  passed: boolean;
}

export interface ClaimAuditEntry {
  id: string;
  action: string;
  actor_type: string;
  actor_name: string;
  details?: Record<string, unknown>;
  created_at: string;
}

export interface Claim {
  id: string;
  claim_number: string;
  claim_type: 'AHCIP' | 'WCB';
  state: string;
  patient_id: string;
  patient_name?: string;
  patient_phn?: string;
  physician_id: string;
  date_of_service: string;
  functional_centre?: string;
  encounter_type?: string;
  referring_provider_id?: string;
  referring_provider_name?: string;
  time_spent?: number;
  import_source: string;
  line_items: ClaimLineItem[];
  total_fee: string;
  total_assessed?: string | null;
  is_clean: boolean;
  validation_results?: ClaimValidationResult[];
  rejection_code?: string | null;
  rejection_reason?: string | null;
  rejection_details?: string | null;
  batch_id?: string | null;
  audit_trail?: ClaimAuditEntry[];
  flags?: ClaimFlag[];
  justifications?: ClaimJustification[];
  created_at: string;
  updated_at: string;
  submitted_at?: string | null;
  assessed_at?: string | null;
}

export interface ClaimFlag {
  id: string;
  type: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  message: string;
  resolved: boolean;
}

export interface ClaimJustification {
  id: string;
  scenario: string;
  justification_text: string;
  created_at: string;
}

export interface FeeCalculation {
  line_items: {
    health_service_code: string;
    base_fee: string;
    modifier_adjustments: { modifier: string; adjustment: string }[];
    calculated_fee: string;
  }[];
  total_fee: string;
}

export interface ClaimFilters {
  state?: string | string[];
  date_from?: string;
  date_to?: string;
  patient_id?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

export interface Batch {
  id: string;
  batch_number: string;
  state: string;
  claims_count: number;
  total_amount: string;
  total_assessed?: string | null;
  submission_date?: string | null;
  assessed_date?: string | null;
  claims?: Claim[];
  created_at: string;
  updated_at: string;
}

export interface BatchFilters {
  state?: string;
  page?: number;
  pageSize?: number;
}

export interface ClaimTemplate {
  id: string;
  name: string;
  description?: string;
  template_type: 'CUSTOM' | 'SPECIALTY_STARTER';
  claim_type: 'AHCIP' | 'WCB';
  line_items: {
    health_service_code: string;
    modifiers?: string[];
    diagnostic_code?: string;
    calls: number;
  }[];
  specialty_code?: string;
  last_used_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---------- Claim Queries ----------

export function useClaims(filters: ClaimFilters = {}) {
  const { state, date_from, date_to, patient_id, search, page = 1, pageSize = 25 } = filters;

  return useQuery({
    queryKey: queryKeys.claims.list({ state, date_from, date_to, patient_id, search, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Claim>>('/api/v1/claims', {
        params: {
          state: Array.isArray(state) ? state.join(',') : state,
          date_from,
          date_to,
          patient_id,
          search,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useClaim(id: string) {
  return useQuery({
    queryKey: queryKeys.claims.detail(id),
    queryFn: () => api.get<ApiResponse<Claim>>(`/api/v1/claims/${id}`),
    enabled: !!id,
  });
}

// ---------- Claim Mutations ----------

export interface CreateClaimInput {
  claim_type: 'AHCIP' | 'WCB';
  patient_id: string;
  date_of_service: string;
  functional_centre?: string;
  encounter_type?: string;
  referring_provider_id?: string;
  time_spent?: number;
  import_source?: string;
  line_items?: {
    health_service_code: string;
    modifiers?: string[];
    diagnostic_codes?: string[];
    calls?: number;
  }[];
  save_as_draft?: boolean;
}

export function useCreateClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateClaimInput) =>
      api.post<ApiResponse<Claim>>('/api/v1/claims', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useUpdateClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateClaimInput> }) =>
      api.patch<ApiResponse<Claim>>(`/api/v1/claims/${id}`, data),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(variables.id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useValidateClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.post<ApiResponse<Claim>>(`/api/v1/claims/${id}/validate`),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useQueueClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.post<ApiResponse<Claim>>(`/api/v1/claims/${id}/queue`),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useUnqueueClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.post<ApiResponse<Claim>>(`/api/v1/claims/${id}/unqueue`),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useResubmitClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.post<ApiResponse<Claim>>(`/api/v1/claims/${id}/resubmit`),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useWriteOffClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<ApiResponse<Claim>>(`/api/v1/claims/${id}/write-off`, { reason }),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.detail(variables.id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useCalculateFee() {
  return useMutation({
    mutationFn: (data: {
      line_items: {
        health_service_code: string;
        modifiers?: string[];
        calls?: number;
      }[];
      functional_centre?: string;
      date_of_service?: string;
    }) => api.post<ApiResponse<FeeCalculation>>('/api/v1/claims/fee/calculate', data),
  });
}

// ---------- Batch Queries ----------

export function useBatches(filters: BatchFilters = {}) {
  const { state, page = 1, pageSize = 20 } = filters;

  return useQuery({
    queryKey: queryKeys.batches.list({ state, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Batch>>('/api/v1/batches', {
        params: {
          state,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useBatch(id: string) {
  return useQuery({
    queryKey: queryKeys.batches.detail(id),
    queryFn: () => api.get<ApiResponse<Batch>>(`/api/v1/batches/${id}`),
    enabled: !!id,
  });
}

// ---------- Template Queries ----------

export function useClaimTemplates() {
  return useQuery({
    queryKey: queryKeys.claims.templates(),
    queryFn: () =>
      api.get<PaginatedResponse<ClaimTemplate>>('/api/v1/claims/templates', {
        params: { page_size: 50 },
      }),
  });
}

export function useCreateTemplate() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: {
      name: string;
      description?: string;
      template_type?: string;
      claim_type: 'AHCIP' | 'WCB';
      line_items: {
        health_service_code: string;
        modifiers?: string[];
        diagnostic_code?: string;
        calls: number;
      }[];
      specialty_code?: string;
    }) => api.post<ApiResponse<ClaimTemplate>>('/api/v1/claims/templates', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.templates() });
    },
  });
}

export function useDeleteTemplate() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/claims/templates/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.templates() });
    },
  });
}
