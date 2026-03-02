'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { useAuthStore } from '@/stores/auth.store';
import { toast } from 'sonner';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Delegate {
  id: string;
  user_id: string;
  name: string;
  email: string;
  status: 'active' | 'pending' | 'revoked';
  permissions: string[];
  invited_at: string;
  accepted_at?: string;
}

export interface DelegatePhysician {
  provider_id: string;
  physician_name: string;
  billing_number: string;
  permissions: string[];
}

export const DELEGATE_PERMISSIONS = [
  'claims:read',
  'claims:write',
  'claims:submit',
  'patients:read',
  'patients:write',
  'batches:read',
  'batches:submit',
  'wcb:read',
  'wcb:write',
  'analytics:read',
  'settings:read',
] as const;

export type DelegatePermission = (typeof DELEGATE_PERMISSIONS)[number];

// ---------------------------------------------------------------------------
// Delegates list (for a provider)
// ---------------------------------------------------------------------------

export function useDelegates() {
  return useQuery({
    queryKey: queryKeys.providers.delegates(),
    queryFn: () =>
      api.get<{ data: Delegate[] }>('/api/v1/providers/me/delegates'),
  });
}

export function useInviteDelegate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; permissions: string[] }) =>
      api.post<{ data: Delegate }>('/api/v1/providers/me/delegates/invite', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.delegates() });
      toast.success('Delegate invitation sent');
    },
    onError: () => {
      toast.error('Failed to send delegate invitation');
    },
  });
}

export function useUpdateDelegatePermissions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, permissions }: { id: string; permissions: string[] }) =>
      api.put<{ data: Delegate }>(`/api/v1/providers/me/delegates/${id}/permissions`, { permissions }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.delegates() });
      toast.success('Delegate permissions updated');
    },
    onError: () => {
      toast.error('Failed to update delegate permissions');
    },
  });
}

export function useRevokeDelegate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/providers/me/delegates/${id}/revoke`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.delegates() });
      toast.success('Delegate access revoked');
    },
    onError: () => {
      toast.error('Failed to revoke delegate access');
    },
  });
}

// ---------------------------------------------------------------------------
// Delegate context switching (for delegates who act on behalf of physicians)
// ---------------------------------------------------------------------------

export function useDelegatePhysicians() {
  const { user } = useAuthStore();
  return useQuery({
    queryKey: [...queryKeys.providers.all, 'delegate-physicians'] as const,
    queryFn: () =>
      api.get<{ data: DelegatePhysician[] }>('/api/v1/delegates/me/physicians'),
    enabled: user?.role === 'delegate',
  });
}

export function useSwitchDelegateContext() {
  const { setDelegateContext } = useAuthStore();
  return useMutation({
    mutationFn: (providerId: string) =>
      api.post<{
        data: {
          delegateUserId: string;
          physicianProviderId: string;
          physicianName: string;
          permissions: string[];
        };
      }>(`/api/v1/delegates/me/switch-context/${providerId}`, {}),
    onSuccess: (res) => {
      setDelegateContext(res.data);
      toast.success(`Switched to ${res.data.physicianName}`);
    },
    onError: () => {
      toast.error('Failed to switch context');
    },
  });
}

export function useClearDelegateContext() {
  const { setDelegateContext } = useAuthStore();
  return useMutation({
    mutationFn: () =>
      api.post('/api/v1/delegates/me/context/clear', {}),
    onSuccess: () => {
      setDelegateContext(null);
      toast.success('Returned to your own account');
    },
    onError: () => {
      toast.error('Failed to clear delegate context');
    },
  });
}
