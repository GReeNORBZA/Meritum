'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { useForm, Controller, useFieldArray } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { DatePicker } from '@/components/forms/date-picker';
import { SearchCombobox, type ComboboxOption } from '@/components/forms/search-combobox';
import { PatientSearch } from '@/components/domain/patients/patient-search';
import { FeeBreakdown } from '@/components/domain/claims/fee-breakdown';
import { useCreateClaim, useCalculateFee, type FeeCalculation } from '@/hooks/api/use-claims';
import { api } from '@/lib/api/client';
import type { ApiResponse } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import { formatDateISO } from '@/lib/formatters/date';
import { differenceInDays } from 'date-fns';
import {
  Loader2,
  Plus,
  X,
  AlertTriangle,
  Save,
  Send,
  Info,
} from 'lucide-react';

// ---------- Types ----------

interface ClaimFormValues {
  patient_id: string;
  date_of_service: Date;
  functional_centre: string;
  encounter_type: string;
  referring_provider_id: string;
  time_spent: number | undefined;
  calls: number;
  hsc_codes: { code: string; label: string }[];
  diagnostic_codes: { code: string; label: string }[];
  modifiers: string[];
}

interface ClaimFormProps {
  className?: string;
}

// ---------- Constants ----------

const ENCOUNTER_TYPES = [
  { value: 'office', label: 'Office Visit' },
  { value: 'hospital', label: 'Hospital' },
  { value: 'home', label: 'Home Visit' },
  { value: 'telehealth', label: 'Telehealth' },
  { value: 'other', label: 'Other' },
] as const;

const FUNCTIONAL_CENTRES = [
  { value: 'CLIN', label: 'CLIN - Clinical' },
  { value: 'HOSP', label: 'HOSP - Hospital' },
  { value: 'EMRG', label: 'EMRG - Emergency' },
  { value: 'SURG', label: 'SURG - Surgical' },
  { value: 'DIAG', label: 'DIAG - Diagnostic' },
  { value: 'ANES', label: 'ANES - Anesthesia' },
  { value: 'OBST', label: 'OBST - Obstetrics' },
  { value: 'PSYC', label: 'PSYC - Psychiatry' },
] as const;

const DOS_WARNING_DAYS = 85;

// ---------- HSC Search ----------

async function searchHscCodes(query: string): Promise<ComboboxOption[]> {
  if (!query || query.length < 2) return [];
  try {
    const res = await api.get<ApiResponse<{ code: string; description: string; fee: string }[]>>(
      '/api/v1/ref/hsc/search',
      { params: { q: query, limit: 10 } }
    );
    return (res.data ?? []).map((item) => ({
      value: item.code,
      label: `${item.code} - ${item.description}`,
      description: `Fee: $${item.fee}`,
    }));
  } catch {
    return [];
  }
}

// ---------- Diagnostic Search ----------

async function searchDiagnosticCodes(query: string): Promise<ComboboxOption[]> {
  if (!query || query.length < 2) return [];
  try {
    const res = await api.get<ApiResponse<{ code: string; description: string }[]>>(
      '/api/v1/ref/di/search',
      { params: { q: query, limit: 10 } }
    );
    return (res.data ?? []).map((item) => ({
      value: item.code,
      label: `${item.code} - ${item.description}`,
    }));
  } catch {
    return [];
  }
}

// ---------- Referring Provider Search ----------

async function searchReferringProviders(query: string): Promise<ComboboxOption[]> {
  if (!query || query.length < 2) return [];
  try {
    const res = await api.get<ApiResponse<{ id: string; name: string; cpsa_number: string }[]>>(
      '/api/v1/ref/providers/search',
      { params: { q: query, limit: 10 } }
    );
    return (res.data ?? []).map((item) => ({
      value: item.id,
      label: item.name,
      description: `CPSA: ${item.cpsa_number}`,
    }));
  } catch {
    return [];
  }
}

// ---------- Required Label ----------

function RequiredLabel({ children, htmlFor }: { children: React.ReactNode; htmlFor?: string }) {
  return (
    <Label htmlFor={htmlFor} className="after:content-['*'] after:ml-0.5 after:text-destructive">
      {children}
    </Label>
  );
}

// ---------- Component ----------

function ClaimForm({ className }: ClaimFormProps) {
  const router = useRouter();
  const createClaim = useCreateClaim();
  const calculateFee = useCalculateFee();

  const [feeData, setFeeData] = React.useState<FeeCalculation | null>(null);

  const {
    control,
    handleSubmit,
    watch,
    setValue,
    register,
    formState: { errors, isSubmitting },
  } = useForm<ClaimFormValues>({
    defaultValues: {
      patient_id: '',
      date_of_service: new Date(),
      functional_centre: '',
      encounter_type: 'office',
      referring_provider_id: '',
      time_spent: undefined,
      calls: 1,
      hsc_codes: [],
      diagnostic_codes: [],
      modifiers: [],
    },
  });

  const {
    fields: hscFields,
    append: appendHsc,
    remove: removeHsc,
  } = useFieldArray({ control, name: 'hsc_codes' });

  const {
    fields: diagnosticFields,
    append: appendDiagnostic,
    remove: removeDiagnostic,
  } = useFieldArray({ control, name: 'diagnostic_codes' });

  // Watch fields for fee calculation
  const watchedHsc = watch('hsc_codes');
  const watchedModifiers = watch('modifiers');
  const watchedFunctionalCentre = watch('functional_centre');
  const watchedDateOfService = watch('date_of_service');

  // Date of service warning
  const dosWarning = React.useMemo(() => {
    if (!watchedDateOfService) return null;
    const daysAgo = differenceInDays(new Date(), watchedDateOfService);
    if (daysAgo > DOS_WARNING_DAYS) {
      return `Date of service is ${daysAgo} days ago. Claims older than 90 days may be rejected.`;
    }
    return null;
  }, [watchedDateOfService]);

  // Real-time fee calculation
  React.useEffect(() => {
    if (!watchedHsc || watchedHsc.length === 0) {
      setFeeData(null);
      return;
    }

    const timer = setTimeout(() => {
      calculateFee.mutate(
        {
          line_items: watchedHsc.map((hsc) => ({
            health_service_code: hsc.code,
            modifiers: watchedModifiers,
          })),
          functional_centre: watchedFunctionalCentre || undefined,
          date_of_service: watchedDateOfService
            ? formatDateISO(watchedDateOfService)
            : undefined,
        },
        {
          onSuccess: (res) => {
            setFeeData(res.data);
          },
        }
      );
    }, 500);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [watchedHsc, watchedModifiers, watchedFunctionalCentre, watchedDateOfService]);

  // Temporary state for HSC / diagnostic combobox
  const [hscSearchValue, setHscSearchValue] = React.useState('');
  const [diagnosticSearchValue, setDiagnosticSearchValue] = React.useState('');
  const [modifierInput, setModifierInput] = React.useState('');

  const handleAddHsc = React.useCallback(
    (value: string) => {
      if (!value || hscFields.length >= 3) return;
      if (hscFields.some((f) => f.code === value)) return;
      appendHsc({ code: value, label: value });
      setHscSearchValue('');
    },
    [hscFields, appendHsc]
  );

  const handleAddDiagnostic = React.useCallback(
    (value: string) => {
      if (!value || diagnosticFields.length >= 3) return;
      if (diagnosticFields.some((f) => f.code === value)) return;
      appendDiagnostic({ code: value, label: value });
      setDiagnosticSearchValue('');
    },
    [diagnosticFields, appendDiagnostic]
  );

  const handleAddModifier = React.useCallback(() => {
    const trimmed = modifierInput.trim().toUpperCase();
    if (!trimmed) return;
    const current = watch('modifiers') ?? [];
    if (current.includes(trimmed)) return;
    setValue('modifiers', [...current, trimmed]);
    setModifierInput('');
  }, [modifierInput, watch, setValue]);

  const handleRemoveModifier = React.useCallback(
    (mod: string) => {
      const current = watch('modifiers') ?? [];
      setValue(
        'modifiers',
        current.filter((m) => m !== mod)
      );
    },
    [watch, setValue]
  );

  const submitClaim = async (data: ClaimFormValues, saveAsDraft: boolean) => {
    const payload = {
      claim_type: 'AHCIP' as const,
      patient_id: data.patient_id,
      date_of_service: formatDateISO(data.date_of_service),
      functional_centre: data.functional_centre || undefined,
      encounter_type: data.encounter_type || undefined,
      referring_provider_id: data.referring_provider_id || undefined,
      time_spent: data.time_spent || undefined,
      import_source: 'MANUAL' as const,
      line_items: data.hsc_codes.map((hsc) => ({
        health_service_code: hsc.code,
        modifiers: data.modifiers,
        diagnostic_codes: data.diagnostic_codes.map((d) => d.code),
        calls: data.calls,
      })),
      save_as_draft: saveAsDraft,
    };

    const result = await createClaim.mutateAsync(payload);
    router.push(ROUTES.CLAIM_DETAIL(result.data.id));
  };

  return (
    <div className={`grid gap-6 lg:grid-cols-[1fr_320px] ${className ?? ''}`}>
      {/* Main form */}
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Patient & Service Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* 1. Patient Selector */}
            <div className="space-y-2">
              <RequiredLabel htmlFor="patient_id">Patient</RequiredLabel>
              <Controller
                name="patient_id"
                control={control}
                rules={{ required: 'Patient is required' }}
                render={({ field }) => (
                  <PatientSearch
                    value={field.value}
                    onValueChange={field.onChange}
                    placeholder="Search patient by PHN, name, or DOB..."
                  />
                )}
              />
              {errors.patient_id && (
                <p className="text-xs text-destructive">{errors.patient_id.message}</p>
              )}
            </div>

            {/* 2. Date of Service */}
            <div className="space-y-2">
              <RequiredLabel htmlFor="date_of_service">Date of Service</RequiredLabel>
              <Controller
                name="date_of_service"
                control={control}
                rules={{ required: 'Date of service is required' }}
                render={({ field }) => (
                  <DatePicker
                    value={field.value}
                    onChange={field.onChange}
                    placeholder="Select date of service"
                  />
                )}
              />
              {dosWarning && (
                <div className="flex items-start gap-2 rounded-md bg-yellow-50 p-2 text-sm text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{dosWarning}</span>
                </div>
              )}
              {errors.date_of_service && (
                <p className="text-xs text-destructive">{errors.date_of_service.message}</p>
              )}
            </div>

            {/* 3. Practice Setting / Functional Centre */}
            <div className="space-y-2">
              <Label htmlFor="functional_centre">Functional Centre</Label>
              <Controller
                name="functional_centre"
                control={control}
                render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select functional centre..." />
                    </SelectTrigger>
                    <SelectContent>
                      {FUNCTIONAL_CENTRES.map((fc) => (
                        <SelectItem key={fc.value} value={fc.value}>
                          {fc.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>

            {/* 8. Encounter Type */}
            <div className="space-y-2">
              <RequiredLabel htmlFor="encounter_type">Encounter Type</RequiredLabel>
              <Controller
                name="encounter_type"
                control={control}
                rules={{ required: 'Encounter type is required' }}
                render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select encounter type..." />
                    </SelectTrigger>
                    <SelectContent>
                      {ENCOUNTER_TYPES.map((et) => (
                        <SelectItem key={et.value} value={et.value}>
                          {et.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
              {errors.encounter_type && (
                <p className="text-xs text-destructive">{errors.encounter_type.message}</p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Service Codes</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* 4. HSC Codes */}
            <div className="space-y-2">
              <RequiredLabel>HSC Code(s)</RequiredLabel>
              <div className="flex flex-wrap gap-2 mb-2">
                {hscFields.map((field, index) => (
                  <Badge
                    key={field.id}
                    variant="secondary"
                    className="gap-1 font-mono text-sm"
                  >
                    {field.code}
                    <button
                      type="button"
                      onClick={() => removeHsc(index)}
                      className="ml-1 rounded-full hover:bg-muted"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
              {hscFields.length < 3 && (
                <SearchCombobox
                  value={hscSearchValue}
                  onValueChange={handleAddHsc}
                  searchFn={searchHscCodes}
                  placeholder="Search HSC code..."
                  emptyMessage="No HSC codes found."
                />
              )}
              {hscFields.length >= 3 && (
                <p className="text-xs text-muted-foreground">
                  Maximum of 3 HSC codes reached.
                </p>
              )}
              {errors.hsc_codes && (
                <p className="text-xs text-destructive">At least one HSC code is required</p>
              )}
            </div>

            <Separator />

            {/* 5. Diagnostic Codes */}
            <div className="space-y-2">
              <RequiredLabel>Diagnostic Code(s)</RequiredLabel>
              <div className="flex flex-wrap gap-2 mb-2">
                {diagnosticFields.map((field, index) => (
                  <Badge
                    key={field.id}
                    variant="secondary"
                    className="gap-1 font-mono text-sm"
                  >
                    {field.code}
                    <button
                      type="button"
                      onClick={() => removeDiagnostic(index)}
                      className="ml-1 rounded-full hover:bg-muted"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
              {diagnosticFields.length < 3 && (
                <SearchCombobox
                  value={diagnosticSearchValue}
                  onValueChange={handleAddDiagnostic}
                  searchFn={searchDiagnosticCodes}
                  placeholder="Search diagnostic code..."
                  emptyMessage="No diagnostic codes found."
                />
              )}
              {diagnosticFields.length >= 3 && (
                <p className="text-xs text-muted-foreground">
                  Maximum of 3 diagnostic codes reached.
                </p>
              )}
            </div>

            <Separator />

            {/* 6. Modifiers */}
            <div className="space-y-2">
              <Label>Modifiers</Label>
              <div className="flex flex-wrap gap-2 mb-2">
                {(watch('modifiers') ?? []).map((mod) => (
                  <Badge
                    key={mod}
                    variant="outline"
                    className="gap-1 font-mono text-sm"
                  >
                    {mod}
                    <button
                      type="button"
                      onClick={() => handleRemoveModifier(mod)}
                      className="ml-1 rounded-full hover:bg-muted"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
              <div className="flex gap-2">
                <Input
                  value={modifierInput}
                  onChange={(e) => setModifierInput(e.target.value)}
                  placeholder="Enter modifier code..."
                  className="max-w-[200px] font-mono"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddModifier();
                    }
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAddModifier}
                >
                  <Plus className="mr-1 h-3 w-3" />
                  Add
                </Button>
              </div>
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <Info className="h-3 w-3" />
                Modifiers affect fee calculation. Hover over a modifier for details.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Additional Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* 7. Referring Physician */}
            <div className="space-y-2">
              <Label htmlFor="referring_provider_id">Referring Physician</Label>
              <Controller
                name="referring_provider_id"
                control={control}
                render={({ field }) => (
                  <SearchCombobox
                    value={field.value}
                    onValueChange={field.onChange}
                    searchFn={searchReferringProviders}
                    placeholder="Search referring physician..."
                    emptyMessage="No referring physicians found."
                  />
                )}
              />
              <p className="text-xs text-muted-foreground">
                Required for referral-based encounters.
              </p>
            </div>

            {/* 9. Calls */}
            <div className="space-y-2">
              <Label htmlFor="calls">Calls</Label>
              <Input
                id="calls"
                type="number"
                min={1}
                max={99}
                className="max-w-[120px]"
                {...register('calls', {
                  valueAsNumber: true,
                  min: { value: 1, message: 'Minimum 1 call' },
                })}
              />
              {errors.calls && (
                <p className="text-xs text-destructive">{errors.calls.message}</p>
              )}
            </div>

            {/* 10. Time Spent */}
            <div className="space-y-2">
              <Label htmlFor="time_spent">Time Spent (minutes)</Label>
              <Input
                id="time_spent"
                type="number"
                min={0}
                className="max-w-[120px]"
                {...register('time_spent', { valueAsNumber: true })}
              />
              <p className="text-xs text-muted-foreground">
                Required for time-based HSC codes.
              </p>
              {errors.time_spent && (
                <p className="text-xs text-destructive">{errors.time_spent.message}</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Action Buttons */}
        <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            disabled={isSubmitting || createClaim.isPending}
            onClick={handleSubmit((data) => submitClaim(data, true))}
          >
            {createClaim.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Save className="mr-2 h-4 w-4" />
            )}
            Save as Draft
          </Button>
          <Button
            type="button"
            disabled={isSubmitting || createClaim.isPending}
            onClick={handleSubmit((data) => submitClaim(data, false))}
          >
            {createClaim.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            Queue for Submission
          </Button>
        </div>

        {createClaim.isError && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {createClaim.error instanceof Error
              ? createClaim.error.message
              : 'Failed to create claim. Please try again.'}
          </div>
        )}
      </div>

      {/* Sidebar - Fee Breakdown */}
      <div className="space-y-4">
        <FeeBreakdown
          feeData={feeData}
          isLoading={calculateFee.isPending}
        />

        {/* Quick info card */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Info className="h-4 w-4" />
              Billing Tips
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-muted-foreground">
            <p>
              Claims must be submitted within 90 days of the date of service.
            </p>
            <p>
              Ensure the correct functional centre is selected for accurate fee
              calculation.
            </p>
            <p>
              Time-based codes require the time spent field to be completed.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export { ClaimForm };
export type { ClaimFormProps };
