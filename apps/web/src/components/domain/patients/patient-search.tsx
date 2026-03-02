'use client';

import * as React from 'react';
import { SearchCombobox, type ComboboxOption } from '@/components/forms/search-combobox';
import { api } from '@/lib/api/client';
import { maskPhn } from '@/lib/formatters/phn';
import { formatDate } from '@/lib/formatters/date';
import type { Patient } from '@/hooks/api/use-patients';
import type { ApiResponse } from '@/lib/api/client';

// ---------- Props ----------

interface PatientSearchProps {
  value: string;
  onValueChange: (value: string) => void;
  onPatientSelect?: (patient: Patient | null) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

// ---------- Component ----------

function PatientSearch({
  value,
  onValueChange,
  onPatientSelect,
  placeholder = 'Search patient by PHN, name, or DOB...',
  disabled,
  className,
}: PatientSearchProps) {
  const patientsCache = React.useRef<Map<string, Patient>>(new Map());

  const searchFn = React.useCallback(
    async (query: string): Promise<ComboboxOption[]> => {
      if (!query || query.length < 2) return [];

      try {
        const response = await api.get<ApiResponse<Patient[]>>(
          '/api/v1/patients/search',
          {
            params: { q: query, limit: 10 },
          }
        );

        const patients = response.data ?? [];

        // Cache patients for later retrieval
        patients.forEach((p) => {
          patientsCache.current.set(p.id, p);
        });

        return patients.map((patient) => ({
          value: patient.id,
          label: `${patient.last_name}, ${patient.first_name}`,
          description: [
            patient.phn ? maskPhn(patient.phn) : null,
            formatDate(patient.date_of_birth),
          ]
            .filter(Boolean)
            .join(' | '),
        }));
      } catch {
        return [];
      }
    },
    []
  );

  const handleValueChange = React.useCallback(
    (newValue: string) => {
      onValueChange(newValue);
      if (onPatientSelect) {
        const patient = patientsCache.current.get(newValue) ?? null;
        onPatientSelect(patient);
      }
    },
    [onValueChange, onPatientSelect]
  );

  return (
    <SearchCombobox
      value={value}
      onValueChange={handleValueChange}
      searchFn={searchFn}
      placeholder={placeholder}
      emptyMessage="No patients found. Try a different search term."
      disabled={disabled}
      className={className}
    />
  );
}

export { PatientSearch };
export type { PatientSearchProps };
