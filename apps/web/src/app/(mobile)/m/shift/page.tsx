'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ROUTES } from '@/config/routes';
import { EncounterForm } from '@/components/domain/mobile/encounter-form';
import {
  useActiveShift,
  useStartShift,
  useEndShift,
  useShiftEncounters,
} from '@/hooks/api/use-mobile';
import {
  PlayCircle,
  StopCircle,
  CalendarDays,
  Loader2,
  User,
  Clock,
} from 'lucide-react';

function formatElapsed(startedAt: string): string {
  const start = new Date(startedAt).getTime();
  const now = Date.now();
  const diffSec = Math.max(0, Math.floor((now - start) / 1000));
  const hours = Math.floor(diffSec / 3600);
  const minutes = Math.floor((diffSec % 3600) / 60);
  const seconds = diffSec % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export default function MobileShiftPage() {
  const router = useRouter();
  const { data: activeShiftData, isLoading: isLoadingShift } = useActiveShift();
  const startShift = useStartShift();
  const endShift = useEndShift();

  const activeShift = activeShiftData?.data ?? null;
  const shiftId = activeShift?.id ?? '';

  const { data: encountersData, refetch: refetchEncounters } = useShiftEncounters(shiftId);
  const encounters = encountersData?.data ?? [];

  // Live timer
  const [elapsed, setElapsed] = useState('00:00:00');

  const updateTimer = useCallback(() => {
    if (activeShift?.started_at) {
      setElapsed(formatElapsed(activeShift.started_at));
    }
  }, [activeShift?.started_at]);

  useEffect(() => {
    if (!activeShift?.started_at) {
      setElapsed('00:00:00');
      return;
    }
    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [activeShift?.started_at, updateTimer]);

  const handleStartShift = () => {
    startShift.mutate(undefined);
  };

  const handleEndShift = () => {
    if (activeShift) {
      endShift.mutate(activeShift.id);
    }
  };

  if (isLoadingShift) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">ED Shift</h1>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push(ROUTES.MOBILE_SCHEDULE)}
        >
          <CalendarDays className="mr-1 h-4 w-4" />
          Schedule
        </Button>
      </div>

      {/* Shift Status Card */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">
            {activeShift ? 'Active Shift' : 'No Active Shift'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {activeShift ? (
            <>
              {/* Timer Display */}
              <div className="flex flex-col items-center gap-1 py-2">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-green-600 animate-pulse" />
                  <span className="text-3xl font-mono font-bold tracking-wider">
                    {elapsed}
                  </span>
                </div>
                {activeShift.location_name && (
                  <p className="text-xs text-muted-foreground">
                    {activeShift.location_name}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  {encounters.length} encounter{encounters.length !== 1 ? 's' : ''} logged
                </p>
              </div>

              <Button
                variant="destructive"
                className="w-full"
                onClick={handleEndShift}
                disabled={endShift.isPending}
              >
                {endShift.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <StopCircle className="mr-2 h-4 w-4" />
                )}
                End Shift
              </Button>
            </>
          ) : (
            <Button
              className="w-full"
              onClick={handleStartShift}
              disabled={startShift.isPending}
            >
              {startShift.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <PlayCircle className="mr-2 h-4 w-4" />
              )}
              Start Shift
            </Button>
          )}

          {(startShift.isError || endShift.isError) && (
            <p className="text-xs text-destructive text-center">
              {(startShift.error ?? endShift.error) instanceof Error
                ? ((startShift.error ?? endShift.error) as Error).message
                : 'An error occurred'}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Encounter Form - only visible during active shift */}
      {activeShift && (
        <EncounterForm
          shiftId={activeShift.id}
          onLogged={() => refetchEncounters()}
        />
      )}

      {/* Encounters List */}
      {activeShift && encounters.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Encounters</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {encounters.map((enc) => (
                <li key={enc.id} className="flex items-center gap-3 py-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                    <User className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {enc.patient_name || enc.patient_phn || 'Unknown Patient'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {enc.encounter_type && `${enc.encounter_type} \u00B7 `}
                      {new Date(enc.logged_at).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </p>
                  </div>
                  {enc.claim_id && (
                    <span className="text-xs text-green-600 font-medium">Claimed</span>
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
