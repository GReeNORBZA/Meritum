'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { PaginatedResponse, ApiResponse } from '@/lib/api/client';
import type { CreatePatient, UpdatePatient } from '@meritum/shared';

// ---------- Types ----------

export interface Patient {
  id: string;
  phn: string | null;
  phn_province: string;
  first_name: string;
  middle_name: string | null;
  last_name: string;
  date_of_birth: string;
  gender: string;
  phone: string | null;
  email: string | null;
  address_line_1: string | null;
  address_line_2: string | null;
  city: string | null;
  province: string | null;
  postal_code: string | null;
  notes: string | null;
  last_visit_date: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PatientEligibility {
  phn_masked: string;
  is_eligible: boolean;
  eligibility_details?: {
    coverage_type?: string;
    effective_date?: string;
    expiry_date?: string;
    out_of_province?: boolean;
  };
  verified_at: string;
  cached: boolean;
}

export interface PatientFilters {
  search?: string;
  page?: number;
  pageSize?: number;
}

// ---------- Queries ----------

export function usePatients(filters: PatientFilters = {}) {
  const { search, page = 1, pageSize = 20 } = filters;

  return useQuery({
    queryKey: queryKeys.patients.list({ search, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Patient>>('/api/v1/patients/search', {
        params: {
          search: search || undefined,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function usePatient(id: string) {
  return useQuery({
    queryKey: queryKeys.patients.detail(id),
    queryFn: () => api.get<ApiResponse<Patient>>(`/api/v1/patients/${id}`),
    enabled: !!id,
  });
}

export function useRecentPatients(limit: number = 5) {
  return useQuery({
    queryKey: queryKeys.patients.recent(),
    queryFn: () =>
      api.get<ApiResponse<Patient[]>>('/api/v1/patients/recent', {
        params: { limit },
      }),
  });
}

export function usePatientEligibility(id: string) {
  return useQuery({
    queryKey: queryKeys.patients.eligibility(id),
    queryFn: () =>
      api.post<ApiResponse<PatientEligibility>>(
        '/api/v1/patients/eligibility/check',
        { patient_id: id }
      ),
    enabled: !!id,
  });
}

// ---------- Mutations ----------

export function useCreatePatient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreatePatient) =>
      api.post<ApiResponse<Patient>>('/api/v1/patients', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.patients.all });
    },
  });
}

export function useUpdatePatient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdatePatient }) =>
      api.put<ApiResponse<Patient>>(`/api/v1/patients/${id}`, data),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({
        queryKey: queryKeys.patients.detail(variables.id),
      });
      queryClient.invalidateQueries({ queryKey: queryKeys.patients.all });
    },
  });
}

export function useDeletePatient() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/patients/${id}/deactivate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.patients.all });
    },
  });
}
