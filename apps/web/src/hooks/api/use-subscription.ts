'use client';

import { useQuery, useMutation } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';

export function useSubscription() {
  return useQuery({
    queryKey: queryKeys.subscription.status(),
    queryFn: () => api.get<{ data: Record<string, unknown> }>('/api/v1/subscriptions/current'),
  });
}

export function useCreatePortalSession() {
  return useMutation({
    mutationFn: () =>
      api.post<{ data: { url: string } }>('/api/v1/subscriptions/portal', {}),
  });
}
