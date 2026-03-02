'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Stethoscope, Info } from 'lucide-react';

interface PractitionerSectionProps {
  readOnly?: boolean;
}

const PRACTITIONER_ROLES = [
  { value: 'GP', label: 'GP - General Practitioner' },
  { value: 'OR', label: 'OR - Oral/Maxillofacial' },
  { value: 'SP', label: 'SP - Specialist' },
  { value: 'ERS', label: 'ERS - Emergency Room Specialist' },
  { value: 'ANE', label: 'ANE - Anesthesiologist' },
  { value: 'DP', label: 'DP - Dental Professional' },
  { value: 'VSC', label: 'VSC - Visiting Specialist Clinic' },
  { value: 'OIS', label: 'OIS - Occupational Injury Service' },
  { value: 'NP', label: 'NP - Nurse Practitioner' },
] as const;

function PractitionerSection({ readOnly }: PractitionerSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  const roleCode = watch('practitioner_role_code');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Stethoscope className="h-5 w-5" />
          Practitioner Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-start gap-2 rounded-md bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-950 dark:text-blue-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Practitioner details are auto-filled from your provider profile. Update your
            profile settings if any information is incorrect.
          </span>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="practitioner_name">Practitioner Name</Label>
            <Input
              id="practitioner_name"
              placeholder="Auto-filled from profile"
              readOnly={readOnly}
              {...register('practitioner_name')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="practitioner_billing_number">Billing Number</Label>
            <Input
              id="practitioner_billing_number"
              placeholder="Auto-filled from profile"
              className="font-mono"
              readOnly={readOnly}
              {...register('practitioner_billing_number')}
            />
          </div>

          <div className="space-y-2">
            <Label>Role Code</Label>
            <Select
              value={roleCode || ''}
              onValueChange={(v) =>
                setValue('practitioner_role_code', v, { shouldValidate: true })
              }
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select role..." />
              </SelectTrigger>
              <SelectContent>
                {PRACTITIONER_ROLES.map((role) => (
                  <SelectItem key={role.value} value={role.value}>
                    {role.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.practitioner_role_code && (
              <p className="text-xs text-destructive">
                {errors.practitioner_role_code.message as string}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="practitioner_contract_id">Contract ID</Label>
            <Input
              id="practitioner_contract_id"
              placeholder="Auto-filled from profile"
              className="font-mono"
              readOnly={readOnly}
              {...register('practitioner_contract_id')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="practitioner_phone">Phone</Label>
            <Input
              id="practitioner_phone"
              type="tel"
              placeholder="(403) 555-0100"
              readOnly={readOnly}
              {...register('practitioner_phone')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="practitioner_facility_type">Facility Type</Label>
            <Select
              value={watch('practitioner_facility_type') || ''}
              onValueChange={(v) =>
                setValue('practitioner_facility_type', v, { shouldValidate: true })
              }
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select facility..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="C">Clinic</SelectItem>
                <SelectItem value="F">Facility (Non-Hospital)</SelectItem>
                <SelectItem value="H">Hospital</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export { PractitionerSection };
export type { PractitionerSectionProps };
