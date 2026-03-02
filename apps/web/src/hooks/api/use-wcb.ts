'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { PaginatedResponse, ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export interface WcbInjury {
  part_of_body_code: string;
  side_of_body_code?: string;
  nature_of_injury_code: string;
}

export interface WcbPrescription {
  prescription_name: string;
  strength: string;
  daily_intake: string;
}

export interface WcbConsultation {
  category: string;
  type_code: string;
  details: string;
  expedite_requested?: string;
}

export interface WcbWorkRestriction {
  activity_type: string;
  restriction_level: string;
  hours_per_day?: number;
  max_weight?: string;
}

export interface WcbAttachment {
  file_name: string;
  file_type: string;
  file_content_b64: string;
  file_description: string;
}

export interface WcbInvoiceLine {
  line_type: string;
  health_service_code?: string;
  diagnostic_code_1?: string;
  diagnostic_code_2?: string;
  diagnostic_code_3?: string;
  modifier_1?: string;
  modifier_2?: string;
  modifier_3?: string;
  calls?: number;
  encounters?: number;
  date_of_service_from?: string;
  date_of_service_to?: string;
  facility_type_override?: string;
  skill_code_override?: string;
  amount?: string;
  quantity?: number;
  supply_description?: string;
  correction_pair_id?: number;
  adjustment_indicator?: string;
  billing_number_override?: string;
}

export interface WcbClaim {
  id: string;
  form_id: string;
  patient_id: string;
  patient_name?: string;
  patient_phn?: string;
  state: string;
  wcb_claim_number?: string;
  date_of_injury?: string;
  date_of_examination?: string;
  report_completion_date?: string;
  employer_name?: string;
  employer_location?: string;
  employer_city?: string;
  employer_province?: string;
  employer_phone_number?: string;
  worker_job_title?: string;
  injury_developed_over_time?: string;
  injury_description?: string;
  symptoms?: string;
  objective_findings?: string;
  current_diagnosis?: string;
  diagnostic_code_1?: string;
  diagnostic_code_2?: string;
  diagnostic_code_3?: string;
  narcotics_prescribed?: string;
  treatment_plan_text?: string;
  missed_work_beyond_accident?: string;
  patient_returned_to_work?: string;
  date_returned_to_work?: string;
  estimated_rtw_date?: string;
  additional_comments?: string;
  timing_tier?: string;
  total_fee?: string;
  injuries?: WcbInjury[];
  prescriptions?: WcbPrescription[];
  consultations?: WcbConsultation[];
  work_restrictions?: WcbWorkRestriction[];
  invoice_lines?: WcbInvoiceLine[];
  attachments?: WcbAttachment[];
  validation_results?: {
    check_id: string;
    severity: string;
    message: string;
    field?: string;
  }[];
  deadline_info?: {
    same_day_deadline?: string;
    on_time_deadline?: string;
    is_past_deadline: boolean;
    business_days_remaining?: number;
  };
  created_at: string;
  updated_at: string;
  submitted_at?: string;
}

export interface WcbClaimFilters {
  form_id?: string;
  state?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

export interface WcbFormConfig {
  form_id: string;
  sections: {
    name: string;
    active: boolean;
    fields: {
      name: string;
      required: boolean;
      conditional: boolean;
      type: string;
      max_length?: number;
    }[];
  }[];
}

// ---------- Queries ----------

export function useWcbClaims(filters: WcbClaimFilters = {}) {
  const { form_id, state, search, page = 1, pageSize = 25 } = filters;

  return useQuery({
    queryKey: queryKeys.wcb.list({ form_id, state, search, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<WcbClaim>>('/api/v1/wcb/claims', {
        params: {
          form_id,
          state,
          search,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useWcbClaim(id: string) {
  return useQuery({
    queryKey: queryKeys.wcb.detail(id),
    queryFn: () => api.get<ApiResponse<WcbClaim>>(`/api/v1/wcb/claims/${id}`),
    enabled: !!id,
  });
}

export function useWcbFormConfig(formType: string) {
  return useQuery({
    queryKey: queryKeys.wcb.formSchema(formType),
    queryFn: () =>
      api.get<ApiResponse<WcbFormConfig>>(`/api/v1/wcb/form-config/${formType}`),
    enabled: !!formType,
  });
}

// ---------- Mutations ----------

export function useCreateWcbClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      api.post<ApiResponse<WcbClaim>>('/api/v1/wcb/claims', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.wcb.all });
    },
  });
}

export function useUpdateWcbClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.put<ApiResponse<WcbClaim>>(`/api/v1/wcb/claims/${id}`, data),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.wcb.detail(variables.id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.wcb.all });
    },
  });
}

export function useSubmitWcbClaim() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) =>
      api.post<ApiResponse<WcbClaim>>(`/api/v1/wcb/claims/${id}/validate`),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.wcb.detail(id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.wcb.all });
    },
  });
}
