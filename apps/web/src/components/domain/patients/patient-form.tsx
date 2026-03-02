'use client';

import * as React from 'react';
import { createPatientSchema, updatePatientSchema } from '@meritum/shared';
import type { CreatePatient, UpdatePatient } from '@meritum/shared';
import { FormWrapper, FormField, FormSubmit } from '@/components/forms/form-wrapper';
import { PhnInput } from '@/components/forms/phn-input';
import { DatePicker } from '@/components/forms/date-picker';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { parseISO } from 'date-fns';
import { formatDateISO } from '@/lib/formatters/date';
import type { Patient } from '@/hooks/api/use-patients';

// ---------- Constants ----------

const GENDER_OPTIONS = [
  { value: 'M', label: 'Male' },
  { value: 'F', label: 'Female' },
  { value: 'X', label: 'Other' },
] as const;

const PROVINCE_OPTIONS = [
  { value: 'AB', label: 'Alberta' },
  { value: 'BC', label: 'British Columbia' },
  { value: 'SK', label: 'Saskatchewan' },
  { value: 'MB', label: 'Manitoba' },
  { value: 'ON', label: 'Ontario' },
  { value: 'QC', label: 'Quebec' },
  { value: 'NB', label: 'New Brunswick' },
  { value: 'NS', label: 'Nova Scotia' },
  { value: 'PE', label: 'Prince Edward Island' },
  { value: 'NL', label: 'Newfoundland and Labrador' },
  { value: 'YT', label: 'Yukon' },
  { value: 'NT', label: 'Northwest Territories' },
  { value: 'NU', label: 'Nunavut' },
] as const;

// ---------- Props ----------

interface PatientFormProps {
  initialValues?: Patient;
  onSubmit: (data: CreatePatient | UpdatePatient) => void;
  isSubmitting?: boolean;
  mode?: 'create' | 'edit';
}

// ---------- Component ----------

function PatientForm({
  initialValues,
  onSubmit,
  isSubmitting = false,
  mode = 'create',
}: PatientFormProps) {
  const isEdit = mode === 'edit';
  const schema = isEdit ? updatePatientSchema : createPatientSchema;

  const defaultValues = React.useMemo(() => {
    if (initialValues) {
      return {
        phn: initialValues.phn ?? '',
        phn_province: initialValues.phn_province ?? 'AB',
        first_name: initialValues.first_name ?? '',
        middle_name: initialValues.middle_name ?? '',
        last_name: initialValues.last_name ?? '',
        date_of_birth: initialValues.date_of_birth ?? '',
        gender: initialValues.gender ?? 'M',
        phone: initialValues.phone ?? '',
        email: initialValues.email ?? '',
        address_line_1: initialValues.address_line_1 ?? '',
        address_line_2: initialValues.address_line_2 ?? '',
        city: initialValues.city ?? '',
        province: initialValues.province ?? 'AB',
        postal_code: initialValues.postal_code ?? '',
        notes: initialValues.notes ?? '',
      };
    }
    return {
      phn: '',
      phn_province: 'AB',
      first_name: '',
      middle_name: '',
      last_name: '',
      date_of_birth: '',
      gender: 'M',
      phone: '',
      email: '',
      address_line_1: '',
      address_line_2: '',
      city: '',
      province: 'AB',
      postal_code: '',
      notes: '',
    };
  }, [initialValues]);

  const handleSubmit = (data: Record<string, unknown>) => {
    // Strip formatting from PHN
    const phnRaw = typeof data.phn === 'string'
      ? data.phn.replace(/\D/g, '')
      : null;

    onSubmit({
      ...data,
      phn: phnRaw && phnRaw.length === 9 ? phnRaw : null,
    } as CreatePatient | UpdatePatient);
  };

  return (
    <FormWrapper
      schema={schema}
      defaultValues={defaultValues as any}
      onSubmit={handleSubmit as any}
    >
      {(form) => (
        <>
          {/* Identity Section */}
          <Card>
            <CardHeader>
              <CardTitle>Patient Identity</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <FormField name="phn" label="Personal Health Number (PHN)">
                {({ field }) => (
                  <PhnInput
                    value={field.value}
                    onChange={field.onChange}
                    onBlur={field.onBlur}
                  />
                )}
              </FormField>

              <FormField name="phn_province" label="PHN Province">
                {({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select province" />
                    </SelectTrigger>
                    <SelectContent>
                      {PROVINCE_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.value} - {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </FormField>

              <FormField name="first_name" label="First Name" required>
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="First name"
                    autoComplete="given-name"
                  />
                )}
              </FormField>

              <FormField name="last_name" label="Last Name" required>
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="Last name"
                    autoComplete="family-name"
                  />
                )}
              </FormField>

              <FormField name="middle_name" label="Middle Name">
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="Middle name (optional)"
                    autoComplete="additional-name"
                  />
                )}
              </FormField>

              <FormField name="date_of_birth" label="Date of Birth" required>
                {({ field }) => (
                  <DatePicker
                    value={field.value ? parseISO(field.value) : undefined}
                    onChange={(date) =>
                      field.onChange(date ? formatDateISO(date) : '')
                    }
                    placeholder="Select date of birth"
                  />
                )}
              </FormField>

              <FormField name="gender" label="Gender" required>
                {({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select gender" />
                    </SelectTrigger>
                    <SelectContent>
                      {GENDER_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </FormField>
            </CardContent>
          </Card>

          {/* Contact Section */}
          <Card>
            <CardHeader>
              <CardTitle>Contact Information</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <FormField name="phone" label="Phone Number">
                {({ field }) => (
                  <Input
                    {...field}
                    type="tel"
                    placeholder="(403) 555-0123"
                    autoComplete="tel"
                  />
                )}
              </FormField>

              <FormField name="email" label="Email">
                {({ field }) => (
                  <Input
                    {...field}
                    type="email"
                    placeholder="patient@example.com"
                    autoComplete="email"
                  />
                )}
              </FormField>
            </CardContent>
          </Card>

          {/* Address Section */}
          <Card>
            <CardHeader>
              <CardTitle>Address</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <FormField name="address_line_1" label="Address Line 1" className="sm:col-span-2">
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="Street address"
                    autoComplete="address-line1"
                  />
                )}
              </FormField>

              <FormField name="address_line_2" label="Address Line 2" className="sm:col-span-2">
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="Apartment, suite, unit, etc. (optional)"
                    autoComplete="address-line2"
                  />
                )}
              </FormField>

              <FormField name="city" label="City">
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="City"
                    autoComplete="address-level2"
                  />
                )}
              </FormField>

              <FormField name="province" label="Province">
                {({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select province" />
                    </SelectTrigger>
                    <SelectContent>
                      {PROVINCE_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.value} - {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </FormField>

              <FormField name="postal_code" label="Postal Code">
                {({ field }) => (
                  <Input
                    {...field}
                    placeholder="T2P 1A1"
                    autoComplete="postal-code"
                    maxLength={7}
                  />
                )}
              </FormField>
            </CardContent>
          </Card>

          {/* Notes Section */}
          <Card>
            <CardHeader>
              <CardTitle>Notes</CardTitle>
            </CardHeader>
            <CardContent>
              <FormField name="notes" label="Internal Notes">
                {({ field }) => (
                  <Textarea
                    {...field}
                    placeholder="Optional notes about this patient..."
                    rows={4}
                  />
                )}
              </FormField>
            </CardContent>
          </Card>

          {/* Submit */}
          <div className="flex justify-end gap-3">
            <FormSubmit
              isLoading={isSubmitting}
              loadingText={isEdit ? 'Saving...' : 'Creating...'}
            >
              {isEdit ? 'Save Changes' : 'Create Patient'}
            </FormSubmit>
          </div>
        </>
      )}
    </FormWrapper>
  );
}

export { PatientForm };
export type { PatientFormProps };
