'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export interface HscCode {
  code: string;
  description: string;
  fee: number;
  modifier_eligible: boolean;
}

export interface DiagnosticCode {
  code: string;
  description: string;
  type: 'ICD-9' | 'ICD-10';
  chapter?: string;
}

export interface ReferringProvider {
  billing_number: string;
  first_name: string;
  last_name: string;
  specialty?: string;
  city?: string;
}

export interface FavouriteCode {
  code: string;
  description: string;
  fee: number;
  pinned: boolean;
}

export interface HscGuidance {
  code: string;
  description: string;
  billing_rules: string[];
  common_rejections: Array<{
    reason: string;
    prevention_tip: string;
  }>;
  documentation_requirements: string[];
  notes: string | null;
  effective_date: string;
  category: string;
}

export interface BundlingRule {
  codes: string[];
  rule_type: 'inclusive' | 'exclusive' | 'conditional';
  message: string;
  severity: 'error' | 'warning' | 'info';
  suggestion?: string;
}

export interface CrosswalkMapping {
  icd9_code: string;
  icd9_description: string;
  match_confidence: 'exact' | 'approximate' | 'partial';
  notes?: string;
}

// ---------- Queries ----------

/**
 * Search HSC (Health Service Codes) by code or description.
 * Enabled only when query is at least 2 characters.
 */
export function useHscSearch(query: string) {
  return useQuery({
    queryKey: queryKeys.reference.hsc(query),
    queryFn: () =>
      api.get<ApiResponse<HscCode[]>>('/api/v1/ref/hsc/search', {
        params: { q: query },
      }),
    enabled: query.length >= 2,
    staleTime: 5 * 60 * 1000, // HSC codes rarely change; cache 5 minutes
  });
}

/**
 * Search diagnostic codes (ICD-9 / ICD-10) by code or description.
 * Enabled only when query is at least 2 characters.
 */
export function useDiagnosticSearch(query: string) {
  return useQuery({
    queryKey: queryKeys.reference.di(query),
    queryFn: () =>
      api.get<ApiResponse<DiagnosticCode[]>>('/api/v1/ref/di/search', {
        params: { q: query },
      }),
    enabled: query.length >= 2,
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Search referring providers by name or billing number.
 * Enabled only when query is at least 2 characters.
 */
export function useReferringProviderSearch(query: string) {
  return useQuery({
    queryKey: queryKeys.reference.referringProviders(query),
    queryFn: () =>
      api.get<ApiResponse<ReferringProvider[]>>(
        '/api/v1/ref/providers/search',
        { params: { q: query } }
      ),
    enabled: query.length >= 2,
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Fetch the user's saved favourite HSC codes.
 */
export function useFavouriteCodes() {
  return useQuery({
    queryKey: queryKeys.reference.favourites(),
    queryFn: () =>
      api.get<ApiResponse<FavouriteCode[]>>('/api/v1/ref/hsc/favourites'),
    staleTime: 60 * 1000,
  });
}

/**
 * Toggle a favourite HSC code (pin/unpin).
 * Optimistically updates the cache and rolls back on error.
 */
export function useToggleFavourite() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (code: string) =>
      api.post<ApiResponse<{ pinned: boolean }>>(
        `/api/v1/favourites`,
        { health_service_code: code }
      ),
    onMutate: async (code) => {
      await queryClient.cancelQueries({
        queryKey: queryKeys.reference.favourites(),
      });

      const previous = queryClient.getQueryData<ApiResponse<FavouriteCode[]>>(
        queryKeys.reference.favourites()
      );

      queryClient.setQueryData<ApiResponse<FavouriteCode[]>>(
        queryKeys.reference.favourites(),
        (old) => {
          if (!old) return old;
          return {
            ...old,
            data: old.data.map((fav) =>
              fav.code === code ? { ...fav, pinned: !fav.pinned } : fav
            ),
          };
        }
      );

      return { previous };
    },
    onError: (_err, _code, context) => {
      if (context?.previous) {
        queryClient.setQueryData(
          queryKeys.reference.favourites(),
          context.previous
        );
      }
    },
    onSettled: () => {
      queryClient.invalidateQueries({
        queryKey: queryKeys.reference.favourites(),
      });
    },
  });
}

/**
 * Fetch billing guidance for a specific HSC code.
 * Enabled only when a code is provided.
 */
export function useHscGuidance(code: string | null) {
  return useQuery({
    queryKey: queryKeys.reference.guidance(code ?? ''),
    queryFn: () =>
      api.get<ApiResponse<HscGuidance>>(
        `/api/v1/ref/guidance/${code}`
      ),
    enabled: !!code,
    staleTime: 10 * 60 * 1000, // Guidance is fairly stable
  });
}

/**
 * Check bundling rules for a set of HSC codes.
 * Enabled only when at least 2 codes are provided.
 */
export function useBundlingCheck(codes: string[]) {
  return useQuery({
    queryKey: queryKeys.reference.bundling(codes),
    queryFn: () =>
      api.post<ApiResponse<BundlingRule[]>>(
        '/api/v1/ref/bundling-rules/check',
        { codes }
      ),
    enabled: codes.length >= 2,
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Look up ICD-10 to ICD-9 crosswalk mappings.
 * Enabled only when an ICD-10 code is provided.
 */
export function useIcdCrosswalk(icd10Code: string) {
  return useQuery({
    queryKey: queryKeys.reference.crosswalk(icd10Code),
    queryFn: () =>
      api.get<ApiResponse<CrosswalkMapping[]>>(
        `/api/v1/ref/icd-crosswalk/${encodeURIComponent(icd10Code)}`
      ),
    enabled: !!icd10Code,
    staleTime: 30 * 60 * 1000, // Crosswalk mappings are very stable
  });
}
