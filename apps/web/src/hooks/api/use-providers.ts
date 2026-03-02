'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { toast } from 'sonner';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProviderProfile {
  id: string;
  first_name: string;
  last_name: string;
  email: string;
  billing_number: string;
  specialty_code: string;
  physician_type: string;
  created_at: string;
  updated_at: string;
}

export interface BusinessArrangement {
  id: string;
  ba_number: string;
  type: 'FFS' | 'PCPCM' | 'ARP';
  status: 'active' | 'inactive' | 'pending';
  effective_date: string;
  end_date?: string;
  facility_number?: string;
  created_at: string;
}

export interface PracticeLocation {
  id: string;
  name: string;
  functional_centre: string;
  facility_number: string;
  address_line1?: string;
  address_line2?: string;
  city: string;
  province: string;
  postal_code: string;
  status: 'active' | 'inactive';
  created_at: string;
}

export interface WcbConfig {
  id: string;
  contract_id: string;
  role_code: string;
  skill_code: string;
  is_default: boolean;
  created_at: string;
}

export interface SubmissionPreferences {
  ahcip_submission_mode: 'AUTO_CLEAN' | 'AUTO_ALL' | 'REQUIRE_APPROVAL';
  wcb_submission_mode: 'AUTO_CLEAN' | 'AUTO_ALL' | 'REQUIRE_APPROVAL';
  batch_review_reminder: boolean;
  deadline_reminder_days: number;
}

export interface FacilityBaMapping {
  id: string;
  facility_number: string;
  ba_id: string;
  ba_number: string;
  priority: number;
}

export interface ScheduleBaMapping {
  id: string;
  day_of_week: number;
  start_time: string;
  end_time: string;
  ba_id: string;
  ba_number: string;
  priority: number;
}

export interface RoutingConfig {
  facility_mappings: FacilityBaMapping[];
  schedule_mappings: ScheduleBaMapping[];
}

// ---------------------------------------------------------------------------
// Provider Profile
// ---------------------------------------------------------------------------

export function useProviderProfile() {
  return useQuery({
    queryKey: queryKeys.providers.profile(),
    queryFn: () =>
      api.get<{ data: ProviderProfile }>('/api/v1/providers/me'),
  });
}

export function useUpdateProviderProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Pick<ProviderProfile, 'first_name' | 'last_name' | 'specialty_code' | 'physician_type'>>) =>
      api.put<{ data: ProviderProfile }>('/api/v1/providers/me', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.profile() });
      toast.success('Profile updated successfully');
    },
    onError: () => {
      toast.error('Failed to update profile');
    },
  });
}

// ---------------------------------------------------------------------------
// Business Arrangements
// ---------------------------------------------------------------------------

export function useBusinessArrangements() {
  return useQuery({
    queryKey: queryKeys.providers.businessArrangements(),
    queryFn: () =>
      api.get<{ data: BusinessArrangement[] }>('/api/v1/providers/me/bas'),
  });
}

export function useCreateBusinessArrangement() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<BusinessArrangement, 'id' | 'created_at'>) =>
      api.post<{ data: BusinessArrangement }>('/api/v1/providers/me/bas', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.businessArrangements() });
      toast.success('Business arrangement created');
    },
    onError: () => {
      toast.error('Failed to create business arrangement');
    },
  });
}

export function useUpdateBusinessArrangement() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<BusinessArrangement> & { id: string }) =>
      api.put<{ data: BusinessArrangement }>(`/api/v1/providers/me/bas/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.businessArrangements() });
      toast.success('Business arrangement updated');
    },
    onError: () => {
      toast.error('Failed to update business arrangement');
    },
  });
}

export function useDeleteBusinessArrangement() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/providers/me/bas/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.businessArrangements() });
      toast.success('Business arrangement deleted');
    },
    onError: () => {
      toast.error('Failed to delete business arrangement');
    },
  });
}

// ---------------------------------------------------------------------------
// Practice Locations
// ---------------------------------------------------------------------------

export function usePracticeLocations() {
  return useQuery({
    queryKey: queryKeys.providers.locations(),
    queryFn: () =>
      api.get<{ data: PracticeLocation[] }>('/api/v1/providers/me/locations'),
  });
}

export function useCreatePracticeLocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<PracticeLocation, 'id' | 'created_at'>) =>
      api.post<{ data: PracticeLocation }>('/api/v1/providers/me/locations', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.locations() });
      toast.success('Location created');
    },
    onError: () => {
      toast.error('Failed to create location');
    },
  });
}

export function useUpdatePracticeLocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<PracticeLocation> & { id: string }) =>
      api.put<{ data: PracticeLocation }>(`/api/v1/providers/me/locations/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.locations() });
      toast.success('Location updated');
    },
    onError: () => {
      toast.error('Failed to update location');
    },
  });
}

export function useDeletePracticeLocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/providers/me/locations/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.locations() });
      toast.success('Location deleted');
    },
    onError: () => {
      toast.error('Failed to delete location');
    },
  });
}

// ---------------------------------------------------------------------------
// WCB Config
// ---------------------------------------------------------------------------

export function useWcbConfigs() {
  return useQuery({
    queryKey: queryKeys.providers.wcbConfig(),
    queryFn: () =>
      api.get<{ data: WcbConfig[] }>('/api/v1/providers/me/wcb'),
  });
}

export function useCreateWcbConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<WcbConfig, 'id' | 'created_at'>) =>
      api.post<{ data: WcbConfig }>('/api/v1/providers/me/wcb', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.wcbConfig() });
      toast.success('WCB configuration created');
    },
    onError: () => {
      toast.error('Failed to create WCB configuration');
    },
  });
}

export function useUpdateWcbConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<WcbConfig> & { id: string }) =>
      api.put<{ data: WcbConfig }>(`/api/v1/providers/me/wcb/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.wcbConfig() });
      toast.success('WCB configuration updated');
    },
    onError: () => {
      toast.error('Failed to update WCB configuration');
    },
  });
}

export function useDeleteWcbConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/providers/me/wcb/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.wcbConfig() });
      toast.success('WCB configuration deleted');
    },
    onError: () => {
      toast.error('Failed to delete WCB configuration');
    },
  });
}

// ---------------------------------------------------------------------------
// Submission Preferences
// ---------------------------------------------------------------------------

export function useSubmissionPreferences() {
  return useQuery({
    queryKey: queryKeys.providers.submissionPreferences(),
    queryFn: () =>
      api.get<{ data: SubmissionPreferences }>('/api/v1/providers/me/submission-preferences'),
  });
}

export function useUpdateSubmissionPreferences() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SubmissionPreferences>) =>
      api.put<{ data: SubmissionPreferences }>('/api/v1/providers/me/submission-preferences', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.submissionPreferences() });
      toast.success('Submission preferences updated');
    },
    onError: () => {
      toast.error('Failed to update submission preferences');
    },
  });
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

export function useRoutingConfig() {
  return useQuery({
    queryKey: queryKeys.providers.routing(),
    queryFn: () =>
      api.get<{ data: RoutingConfig }>('/api/v1/providers/me/routing-config'),
  });
}

export function useCreateFacilityMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<FacilityBaMapping, 'id'>) =>
      api.put<{ data: FacilityBaMapping }>('/api/v1/providers/me/routing-config/facilities', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Facility mapping created');
    },
    onError: () => {
      toast.error('Failed to create facility mapping');
    },
  });
}

export function useUpdateFacilityMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<FacilityBaMapping> & { id: string }) =>
      api.put<{ data: FacilityBaMapping }>('/api/v1/providers/me/routing-config/facilities', { id, ...data }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Facility mapping updated');
    },
    onError: () => {
      toast.error('Failed to update facility mapping');
    },
  });
}

export function useDeleteFacilityMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.put('/api/v1/providers/me/routing-config/facilities', { delete_id: id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Facility mapping deleted');
    },
    onError: () => {
      toast.error('Failed to delete facility mapping');
    },
  });
}

export function useCreateScheduleMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<ScheduleBaMapping, 'id'>) =>
      api.put<{ data: ScheduleBaMapping }>('/api/v1/providers/me/routing-config/schedule', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Schedule mapping created');
    },
    onError: () => {
      toast.error('Failed to create schedule mapping');
    },
  });
}

export function useUpdateScheduleMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<ScheduleBaMapping> & { id: string }) =>
      api.put<{ data: ScheduleBaMapping }>('/api/v1/providers/me/routing-config/schedule', { id, ...data }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Schedule mapping updated');
    },
    onError: () => {
      toast.error('Failed to update schedule mapping');
    },
  });
}

export function useDeleteScheduleMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.put('/api/v1/providers/me/routing-config/schedule', { delete_id: id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.providers.routing() });
      toast.success('Schedule mapping deleted');
    },
    onError: () => {
      toast.error('Failed to delete schedule mapping');
    },
  });
}
