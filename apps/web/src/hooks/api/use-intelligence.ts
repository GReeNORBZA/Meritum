'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export type SuggestionTier = 'A' | 'B' | 'C' | '3';

export interface Suggestion {
  id: string;
  claim_id: string;
  tier: SuggestionTier;
  text: string;
  affected_code: string;
  recommended_action: string;
  confidence_score: number;
  rule_id: string;
  status: 'pending' | 'accepted' | 'dismissed';
  created_at: string;
}

export type AggressivenessLevel = 'conservative' | 'balanced' | 'aggressive';

export interface IntelligencePreferences {
  suggestions_enabled: boolean;
  aggressiveness: AggressivenessLevel;
  auto_apply_tier_a: boolean;
  suppressed_rules: SuppressedRule[];
}

export interface SuppressedRule {
  rule_id: string;
  rule_name: string;
  suppressed_at: string;
}

export interface LearningState {
  total_suggestions: number;
  accepted_count: number;
  dismissed_count: number;
  acceptance_rate: number;
  suppressed_rules: SuppressedRule[];
}

// ---------- Queries ----------

export function useSuggestions(claimId: string) {
  return useQuery({
    queryKey: queryKeys.intelligence.suggestions(claimId),
    queryFn: () =>
      api.get<ApiResponse<Suggestion[]>>(`/api/v1/intelligence/claims/${claimId}/suggestions`),
    enabled: !!claimId,
  });
}

export function useIntelligencePreferences() {
  return useQuery({
    queryKey: queryKeys.intelligence.preferences(),
    queryFn: () =>
      api.get<ApiResponse<IntelligencePreferences>>('/api/v1/intelligence/me/preferences'),
  });
}

export function useLearningState() {
  return useQuery({
    queryKey: queryKeys.intelligence.learningState(),
    queryFn: () =>
      api.get<ApiResponse<LearningState>>('/api/v1/intelligence/me/learning-state'),
  });
}

// ---------- Mutations ----------

export function useAcceptSuggestion() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (suggestionId: string) =>
      api.post<ApiResponse<Suggestion>>(
        `/api/v1/intelligence/suggestions/${suggestionId}/accept`
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
    },
  });
}

export function useDismissSuggestion() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (suggestionId: string) =>
      api.post<ApiResponse<Suggestion>>(
        `/api/v1/intelligence/suggestions/${suggestionId}/dismiss`
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.all });
    },
  });
}

export function useUpdateIntelligencePreferences() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<Omit<IntelligencePreferences, 'suppressed_rules'>>) =>
      api.put<ApiResponse<IntelligencePreferences>>(
        '/api/v1/intelligence/me/preferences',
        data
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.preferences() });
    },
  });
}

export function useUnsuppressRule() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ruleId: string) =>
      api.post<ApiResponse<void>>(
        `/api/v1/intelligence/me/rules/${ruleId}/unsuppress`
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.preferences() });
      queryClient.invalidateQueries({ queryKey: queryKeys.intelligence.learningState() });
    },
  });
}
