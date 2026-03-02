'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DatePicker } from '@/components/forms/date-picker';
import { PatientSearch } from '@/components/domain/patients/patient-search';
import { User } from 'lucide-react';

interface ClaimantSectionProps {
  readOnly?: boolean;
}

function ClaimantSection({ readOnly }: ClaimantSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  const patientId = watch('patient_id');
  const claimantDob = watch('claimant_date_of_birth');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <User className="h-5 w-5" />
          Claimant / Patient Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Patient Search */}
        <div className="space-y-2">
          <Label className="after:content-['*'] after:ml-0.5 after:text-destructive">
            Patient
          </Label>
          <PatientSearch
            value={patientId || ''}
            onValueChange={(v) => setValue('patient_id', v, { shouldValidate: true })}
            placeholder="Search patient by PHN, name, or DOB..."
            disabled={readOnly}
          />
          {errors.patient_id && (
            <p className="text-xs text-destructive">
              {errors.patient_id.message as string}
            </p>
          )}
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="claimant_first_name">First Name</Label>
            <Input
              id="claimant_first_name"
              placeholder="First name"
              readOnly={readOnly}
              {...register('claimant_first_name')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="claimant_last_name">Last Name</Label>
            <Input
              id="claimant_last_name"
              placeholder="Last name"
              readOnly={readOnly}
              {...register('claimant_last_name')}
            />
          </div>

          <div className="space-y-2">
            <Label>Date of Birth</Label>
            <DatePicker
              value={claimantDob ? new Date(claimantDob) : undefined}
              onChange={(d) =>
                setValue(
                  'claimant_date_of_birth',
                  d ? d.toISOString().split('T')[0] : '',
                  { shouldValidate: true }
                )
              }
              placeholder="Select date of birth..."
              disabled={readOnly}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="claimant_phn">PHN</Label>
            <Input
              id="claimant_phn"
              placeholder="e.g. 123456789"
              className="font-mono"
              maxLength={9}
              readOnly={readOnly}
              {...register('claimant_phn')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="claimant_phone">Phone</Label>
            <Input
              id="claimant_phone"
              type="tel"
              placeholder="(403) 555-0100"
              readOnly={readOnly}
              {...register('claimant_phone')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="claimant_employer">Employer</Label>
            <Input
              id="claimant_employer"
              placeholder="Employer name"
              readOnly={readOnly}
              {...register('claimant_employer')}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export { ClaimantSection };
export type { ClaimantSectionProps };
