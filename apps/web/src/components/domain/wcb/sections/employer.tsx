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
import { Building2 } from 'lucide-react';

interface EmployerSectionProps {
  readOnly?: boolean;
}

const PROVINCES = [
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

function EmployerSection({ readOnly }: EmployerSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5" />
          Employer Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="employer_name">Employer Name</Label>
            <Input
              id="employer_name"
              maxLength={50}
              placeholder="Employer name"
              readOnly={readOnly}
              {...register('employer_name')}
            />
            {errors.employer_name && (
              <p className="text-xs text-destructive">
                {errors.employer_name.message as string}
              </p>
            )}
          </div>

          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="employer_location">Address</Label>
            <Input
              id="employer_location"
              maxLength={100}
              placeholder="Street address"
              readOnly={readOnly}
              {...register('employer_location')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="employer_city">City</Label>
            <Input
              id="employer_city"
              maxLength={20}
              placeholder="City"
              readOnly={readOnly}
              {...register('employer_city')}
            />
          </div>

          <div className="space-y-2">
            <Label>Province</Label>
            <Select
              value={watch('employer_province') || ''}
              onValueChange={(v) =>
                setValue('employer_province', v, { shouldValidate: true })
              }
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select province..." />
              </SelectTrigger>
              <SelectContent>
                {PROVINCES.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="employer_phone_number">Phone Number</Label>
            <Input
              id="employer_phone_number"
              type="tel"
              maxLength={24}
              placeholder="(403) 555-0100"
              readOnly={readOnly}
              {...register('employer_phone_number')}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="employer_phone_ext">Extension</Label>
            <Input
              id="employer_phone_ext"
              maxLength={6}
              placeholder="Ext."
              readOnly={readOnly}
              {...register('employer_phone_ext')}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export { EmployerSection };
export type { EmployerSectionProps };
