'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Loader2, CheckCircle2, Send } from 'lucide-react';
import type { ApiResponse } from '@/lib/api/client';

interface QuickClaimInput {
  patient_phn: string;
  date_of_service: string;
  health_service_code: string;
  encounter_type: string;
  diagnostic_codes?: string[];
}

interface QuickClaimResult {
  id: string;
  claim_number: string;
  state: string;
}

export default function MobileClaimPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const [phn, setPhn] = useState('');
  const [dateOfService, setDateOfService] = useState(
    new Date().toISOString().split('T')[0]
  );
  const [hscCode, setHscCode] = useState('');
  const [encounterType, setEncounterType] = useState('');
  const [diagnosticCode, setDiagnosticCode] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const createClaim = useMutation({
    mutationFn: (data: QuickClaimInput) =>
      api.post<ApiResponse<QuickClaimResult>>('/api/v1/claims', {
        claim_type: 'AHCIP',
        patient_phn: data.patient_phn,
        date_of_service: data.date_of_service,
        encounter_type: data.encounter_type,
        import_source: 'MOBILE',
        line_items: [
          {
            health_service_code: data.health_service_code,
            diagnostic_codes: data.diagnostic_codes?.filter(Boolean) ?? [],
            calls: 1,
          },
        ],
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.claims.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.analytics.kpi() });
      setSubmitted(true);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createClaim.mutate({
      patient_phn: phn,
      date_of_service: dateOfService,
      health_service_code: hscCode,
      encounter_type: encounterType,
      diagnostic_codes: diagnosticCode ? [diagnosticCode] : undefined,
    });
  };

  const handleReset = () => {
    setPhn('');
    setDateOfService(new Date().toISOString().split('T')[0]);
    setHscCode('');
    setEncounterType('');
    setDiagnosticCode('');
    setSubmitted(false);
  };

  if (submitted) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold">Quick Claim</h1>
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-10">
            <CheckCircle2 className="h-12 w-12 text-green-500" />
            <p className="text-sm font-medium">Claim submitted successfully</p>
            <div className="flex gap-2 pt-2">
              <Button variant="outline" size="sm" onClick={handleReset}>
                New Claim
              </Button>
              <Button
                size="sm"
                onClick={() => router.push(ROUTES.MOBILE)}
              >
                Home
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold">Quick Claim</h1>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">New AHCIP Claim</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Patient PHN */}
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Patient PHN <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={phn}
                onChange={(e) => setPhn(e.target.value)}
                placeholder="Enter PHN..."
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm"
                inputMode="numeric"
                required
              />
            </div>

            {/* Date of Service */}
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Date of Service <span className="text-destructive">*</span>
              </label>
              <input
                type="date"
                value={dateOfService}
                onChange={(e) => setDateOfService(e.target.value)}
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm"
                required
              />
            </div>

            {/* HSC Code */}
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Health Service Code <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={hscCode}
                onChange={(e) => setHscCode(e.target.value.toUpperCase())}
                placeholder="e.g. 03.05A"
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm font-mono"
                required
              />
              <Button
                type="button"
                variant="link"
                size="sm"
                className="h-auto p-0 text-xs"
                onClick={() => router.push(ROUTES.MOBILE_FAVOURITES)}
              >
                Pick from favourites
              </Button>
            </div>

            {/* Encounter Type */}
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Encounter Type <span className="text-destructive">*</span>
              </label>
              <select
                value={encounterType}
                onChange={(e) => setEncounterType(e.target.value)}
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-background"
                required
              >
                <option value="">Select type...</option>
                <option value="OFFICE">Office Visit</option>
                <option value="HOSPITAL">Hospital</option>
                <option value="ER">Emergency</option>
                <option value="CONSULT">Consultation</option>
                <option value="PROCEDURE">Procedure</option>
                <option value="TELEHEALTH">Telehealth</option>
              </select>
            </div>

            {/* Diagnostic Code (optional) */}
            <div>
              <label className="text-xs font-medium text-muted-foreground">
                Diagnostic Code (optional)
              </label>
              <input
                type="text"
                value={diagnosticCode}
                onChange={(e) => setDiagnosticCode(e.target.value.toUpperCase())}
                placeholder="e.g. 780"
                className="mt-1 w-full rounded-md border px-3 py-2 text-sm font-mono"
              />
            </div>

            {/* Error */}
            {createClaim.isError && (
              <p className="text-xs text-destructive text-center">
                {createClaim.error instanceof Error
                  ? createClaim.error.message
                  : 'Failed to submit claim'}
              </p>
            )}

            {/* Submit */}
            <Button
              type="submit"
              className="w-full"
              disabled={!phn || !hscCode || !encounterType || createClaim.isPending}
            >
              {createClaim.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Send className="mr-2 h-4 w-4" />
              )}
              Submit Claim
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
