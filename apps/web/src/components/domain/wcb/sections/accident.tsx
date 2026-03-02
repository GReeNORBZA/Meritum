'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { DatePicker } from '@/components/forms/date-picker';
import { AlertTriangle } from 'lucide-react';

interface AccidentSectionProps {
  readOnly?: boolean;
}

function AccidentSection({ readOnly }: AccidentSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  const dateOfInjury = watch('date_of_injury');
  const injuryDevelopedOverTime = watch('injury_developed_over_time');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5" />
          Accident / Injury Description
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Date of Injury / Accident</Label>
            <DatePicker
              value={dateOfInjury ? new Date(dateOfInjury) : undefined}
              onChange={(d) =>
                setValue('date_of_injury', d ? d.toISOString().split('T')[0] : '', {
                  shouldValidate: true,
                })
              }
              placeholder="Select date..."
              disabled={readOnly}
            />
            {errors.date_of_injury && (
              <p className="text-xs text-destructive">
                {errors.date_of_injury.message as string}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="worker_job_title">Worker Job Title</Label>
            <Input
              id="worker_job_title"
              maxLength={50}
              placeholder="e.g. Construction Worker"
              readOnly={readOnly}
              {...register('worker_job_title')}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label>Did the injury develop over time?</Label>
          <RadioGroup
            value={injuryDevelopedOverTime || ''}
            onValueChange={(v) =>
              setValue('injury_developed_over_time', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="injury_over_time_yes" />
              <Label htmlFor="injury_over_time_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="injury_over_time_no" />
              <Label htmlFor="injury_over_time_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        <div className="space-y-2">
          <Label htmlFor="injury_description">
            Description of How Injury Occurred
          </Label>
          <Textarea
            id="injury_description"
            rows={4}
            placeholder="Describe how the injury occurred, including the activity the worker was performing at the time..."
            readOnly={readOnly}
            {...register('injury_description')}
          />
          {errors.injury_description && (
            <p className="text-xs text-destructive">
              {errors.injury_description.message as string}
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export { AccidentSection };
export type { AccidentSectionProps };
