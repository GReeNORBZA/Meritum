'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { ApiResponse, PaginatedResponse } from '@/lib/api/client';

// ---------- Types ----------

export type NotificationCategory = 'claims' | 'billing' | 'system';

export interface Notification {
  id: string;
  category: NotificationCategory;
  title: string;
  message: string;
  is_read: boolean;
  related_type?: string;
  related_id?: string;
  created_at: string;
}

export interface UnreadCount {
  count: number;
}

export interface NotificationFilters {
  category?: NotificationCategory;
  page?: number;
  pageSize?: number;
}

export interface ChannelPreference {
  in_app: boolean;
  email: boolean;
}

export interface QuietHoursConfig {
  enabled: boolean;
  start_time: string;
  end_time: string;
  timezone: string;
}

export interface NotificationPreferences {
  channels: {
    claims: ChannelPreference;
    billing: ChannelPreference;
    system: ChannelPreference;
  };
  categories: {
    claims: boolean;
    billing: boolean;
    system: boolean;
  };
  quiet_hours: QuietHoursConfig;
}

// ---------- Queries ----------

export function useNotifications(filters: NotificationFilters = {}) {
  const { category, page = 1, pageSize = 20 } = filters;

  return useQuery({
    queryKey: queryKeys.notifications.feed({ category, page, pageSize }),
    queryFn: () =>
      api.get<PaginatedResponse<Notification>>('/api/v1/notifications', {
        params: {
          category,
          page,
          page_size: pageSize,
        },
      }),
  });
}

export function useUnreadCount() {
  return useQuery({
    queryKey: queryKeys.notifications.unreadCount(),
    queryFn: () =>
      api.get<ApiResponse<UnreadCount>>('/api/v1/notifications/unread-count'),
    refetchInterval: 30000,
  });
}

export function useNotificationPreferences() {
  return useQuery({
    queryKey: queryKeys.notifications.preferences(),
    queryFn: () =>
      api.get<ApiResponse<NotificationPreferences>>('/api/v1/notification-preferences'),
  });
}

// ---------- Mutations ----------

export function useMarkAsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (notificationId: string) =>
      api.post<ApiResponse<void>>(`/api/v1/notifications/${notificationId}/read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications.all });
    },
  });
}

export function useMarkAllAsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () =>
      api.post<ApiResponse<void>>('/api/v1/notifications/read-all'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications.all });
    },
  });
}

export function useDismissNotification() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (notificationId: string) =>
      api.post<ApiResponse<void>>(`/api/v1/notifications/${notificationId}/dismiss`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications.all });
    },
  });
}

export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<NotificationPreferences>) =>
      api.put<ApiResponse<NotificationPreferences>>(
        '/api/v1/notification-preferences',
        data
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.notifications.preferences() });
    },
  });
}
