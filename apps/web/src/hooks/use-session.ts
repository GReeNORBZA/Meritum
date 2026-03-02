'use client';

import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { useAuthStore } from '@/stores/auth.store';

interface SessionResponse {
  data: {
    userId: string;
    email: string;
    fullName: string;
    role: 'physician' | 'delegate' | 'admin';
    providerId: string | null;
    mfaEnabled: boolean;
    onboardingComplete: boolean;
    subscriptionStatus: string;
  };
}

export function useSession() {
  const { setUser, setLoading } = useAuthStore();

  const query = useQuery({
    queryKey: queryKeys.auth.session(),
    queryFn: () => api.get<SessionResponse>('/api/v1/account'),
    retry: false,
    staleTime: 5 * 60 * 1000,
  });

  useEffect(() => {
    if (query.data) {
      setUser(query.data.data);
    } else if (query.isError) {
      setUser(null);
    }
    if (!query.isLoading) {
      setLoading(false);
    }
  }, [query.data, query.isError, query.isLoading, setUser, setLoading]);

  return query;
}
