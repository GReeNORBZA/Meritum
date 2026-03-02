'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import type { ApiResponse } from '@/lib/api/client';

// ---------- Types ----------

export interface Shift {
  id: string;
  physician_id: string;
  location_id?: string;
  location_name?: string;
  started_at: string;
  ended_at?: string | null;
  encounter_count: number;
  status: 'ACTIVE' | 'COMPLETED';
  created_at: string;
  updated_at: string;
}

export interface ShiftEncounter {
  id: string;
  shift_id: string;
  patient_id: string;
  patient_name?: string;
  patient_phn?: string;
  encounter_type?: string;
  logged_at: string;
  claim_id?: string | null;
}

export interface ScheduleEntry {
  id: string;
  date: string;
  location_name?: string;
  start_time: string;
  end_time: string;
  shift_type?: string;
}

export interface StartShiftInput {
  location_id?: string;
}

export interface LogEncounterInput {
  patient_phn?: string;
  patient_id?: string;
  encounter_type?: string;
  barcode_value?: string;
  last_four?: string;
}

// ---------- Shift Queries ----------

export function useActiveShift() {
  return useQuery({
    queryKey: [...queryKeys.mobile.all, 'active-shift'],
    queryFn: () => api.get<ApiResponse<Shift | null>>('/api/v1/shifts/active'),
    refetchInterval: 30_000,
  });
}

export function useShiftEncounters(shiftId: string) {
  return useQuery({
    queryKey: [...queryKeys.mobile.shift(shiftId), 'encounters'],
    queryFn: () =>
      api.get<ApiResponse<ShiftEncounter[]>>(`/api/v1/shifts/${shiftId}/encounters`),
    enabled: !!shiftId,
  });
}

export function useShiftSchedule(month?: string) {
  return useQuery({
    queryKey: [...queryKeys.mobile.schedules(), month],
    queryFn: () =>
      api.get<ApiResponse<ScheduleEntry[]>>('/api/v1/mobile/schedules/calendar', {
        params: { from: month, to: month },
      }),
  });
}

// ---------- Shift Mutations ----------

export function useStartShift() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data?: StartShiftInput) =>
      api.post<ApiResponse<Shift>>('/api/v1/shifts', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.mobile.all });
    },
  });
}

export function useEndShift() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (shiftId: string) =>
      api.post<ApiResponse<Shift>>(`/api/v1/shifts/${shiftId}/end`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.mobile.all });
    },
  });
}

export function useLogEncounter() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ shiftId, data }: { shiftId: string; data: LogEncounterInput }) =>
      api.post<ApiResponse<ShiftEncounter>>(`/api/v1/shifts/${shiftId}/encounters`, data),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({
        queryKey: [...queryKeys.mobile.shift(variables.shiftId), 'encounters'],
      });
      queryClient.invalidateQueries({ queryKey: queryKeys.mobile.all });
    },
  });
}
