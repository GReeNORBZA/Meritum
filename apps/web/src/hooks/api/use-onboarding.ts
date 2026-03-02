'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';

export function useOnboardingProgress() {
  return useQuery({
    queryKey: queryKeys.onboarding.progress(),
    queryFn: () => api.get<{ data: Record<string, unknown> }>('/api/v1/onboarding/progress'),
  });
}

export function useSubmitStep() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { step: number; payload: Record<string, unknown> }) =>
      api.post(`/api/v1/onboarding/steps/${data.step}`, data.payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.onboarding.progress() });
    },
  });
}

export function useCompleteOnboarding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('/api/v1/onboarding/complete', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.onboarding.progress() });
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.session() });
    },
  });
}
