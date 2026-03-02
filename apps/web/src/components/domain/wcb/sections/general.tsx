'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { DatePicker } from '@/components/forms/date-picker';
import { FileText } from 'lucide-react';

interface GeneralSectionProps {
  readOnly?: boolean;
}

function GeneralSection({ readOnly }: GeneralSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  const dateOfInjury = watch('date_of_injury');
  const reportCompletionDate = watch('report_completion_date');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="h-5 w-5" />
          General Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="wcb_claim_number">WCB Claim Number</Label>
            <Input
              id="wcb_claim_number"
              maxLength={7}
              placeholder="e.g. 1234567"
              className="font-mono"
              readOnly={readOnly}
              {...register('wcb_claim_number')}
            />
            {errors.wcb_claim_number && (
              <p className="text-xs text-destructive">
                {errors.wcb_claim_number.message as string}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label>Date of Injury</Label>
            <DatePicker
              value={dateOfInjury ? new Date(dateOfInjury) : undefined}
              onChange={(d) =>
                setValue('date_of_injury', d ? d.toISOString().split('T')[0] : '', {
                  shouldValidate: true,
                })
              }
              placeholder="Select date of injury..."
              disabled={readOnly}
            />
            {errors.date_of_injury && (
              <p className="text-xs text-destructive">
                {errors.date_of_injury.message as string}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label>Report Completion Date</Label>
            <DatePicker
              value={
                reportCompletionDate ? new Date(reportCompletionDate) : undefined
              }
              onChange={(d) =>
                setValue(
                  'report_completion_date',
                  d ? d.toISOString().split('T')[0] : '',
                  { shouldValidate: true }
                )
              }
              placeholder="Select completion date..."
              disabled={readOnly}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="additional_comments">Additional Comments</Label>
          <Textarea
            id="additional_comments"
            rows={3}
            placeholder="Any additional comments for this claim..."
            readOnly={readOnly}
            {...register('additional_comments')}
          />
        </div>
      </CardContent>
    </Card>
  );
}

export { GeneralSection };
export type { GeneralSectionProps };
