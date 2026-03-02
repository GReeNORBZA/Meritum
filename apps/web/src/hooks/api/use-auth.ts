'use client';

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { useAuthStore } from '@/stores/auth.store';
import { useRouter } from 'next/navigation';
import { ROUTES } from '@/config/routes';

// Login mutation
export function useLogin() {
  return useMutation({
    mutationFn: (data: { email: string; password: string }) =>
      api.post<{ data: { mfa_required?: boolean; mfa_session_token?: string; user?: Record<string, unknown> } }>('/api/v1/auth/login', data),
  });
}

// Login MFA step
export function useLoginMfa() {
  const queryClient = useQueryClient();
  const { setUser } = useAuthStore();
  const router = useRouter();
  return useMutation({
    mutationFn: (data: { mfa_session_token: string; totp_code: string }) =>
      api.post<{ data: { user: Record<string, unknown> } }>('/api/v1/auth/login/mfa', data),
    onSuccess: (res) => {
      setUser(res.data.user as any);
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.session() });
      router.push(ROUTES.DASHBOARD);
    },
  });
}

// Login with recovery code
export function useLoginRecovery() {
  const queryClient = useQueryClient();
  const { setUser } = useAuthStore();
  const router = useRouter();
  return useMutation({
    mutationFn: (data: { mfa_session_token: string; recovery_code: string }) =>
      api.post<{ data: { user: Record<string, unknown> } }>('/api/v1/auth/login/recovery', data),
    onSuccess: (res) => {
      setUser(res.data.user as any);
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.session() });
      router.push(ROUTES.DASHBOARD);
    },
  });
}

// Register
export function useRegister() {
  return useMutation({
    mutationFn: (data: { email: string; password: string; full_name: string; phone?: string }) =>
      api.post('/api/v1/auth/register', data),
  });
}

// Verify email
export function useVerifyEmail() {
  return useMutation({
    mutationFn: (data: { token: string }) =>
      api.post('/api/v1/auth/verify-email', data),
  });
}

// Resend verification email
export function useResendVerification() {
  return useMutation({
    mutationFn: (data: { email: string }) =>
      api.post('/api/v1/auth/verify-email/resend', data),
  });
}

// MFA setup
export function useMfaSetup() {
  return useMutation({
    mutationFn: () =>
      api.post<{ data: { qr_code_url: string; secret: string } }>('/api/v1/auth/mfa/setup', {}),
  });
}

// MFA confirm
export function useMfaConfirm() {
  return useMutation({
    mutationFn: (data: { totp_code: string }) =>
      api.post<{ data: { recovery_codes: string[] } }>('/api/v1/auth/mfa/confirm', data),
  });
}

// Password reset request
export function usePasswordResetRequest() {
  return useMutation({
    mutationFn: (data: { email: string }) =>
      api.post('/api/v1/auth/password/reset-request', data),
  });
}

// Password reset
export function usePasswordReset() {
  return useMutation({
    mutationFn: (data: { token: string; new_password: string }) =>
      api.post('/api/v1/auth/password/reset', data),
  });
}

// Delegate accept
export function useDelegateAccept() {
  return useMutation({
    mutationFn: (data: { token: string; full_name?: string; password?: string }) =>
      api.post('/api/v1/delegates/accept', data),
  });
}

// Logout
export function useLogout() {
  const queryClient = useQueryClient();
  const { logout } = useAuthStore();
  const router = useRouter();
  return useMutation({
    mutationFn: () => api.post('/api/v1/auth/logout', {}),
    onSuccess: () => {
      logout();
      queryClient.clear();
      router.push(ROUTES.LOGIN);
    },
  });
}

// Revoke session
export function useRevokeSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (sessionId: string) =>
      api.delete(`/api/v1/sessions/${sessionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.sessions() });
    },
  });
}

// Revoke all other sessions
export function useRevokeAllSessions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.delete('/api/v1/sessions'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.sessions() });
    },
  });
}

// Account update
export function useAccountUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { full_name?: string; phone?: string }) =>
      api.patch('/api/v1/account', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.auth.session() });
    },
  });
}

// Account delete
export function useAccountDelete() {
  return useMutation({
    mutationFn: (data: { password: string; totp_code: string; confirmation: 'DELETE' }) =>
      api.post('/api/v1/account/delete', data),
  });
}
