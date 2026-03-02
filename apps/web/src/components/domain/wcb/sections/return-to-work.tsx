'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { DatePicker } from '@/components/forms/date-picker';
import { Separator } from '@/components/ui/separator';
import { Briefcase } from 'lucide-react';

interface ReturnToWorkSectionProps {
  readOnly?: boolean;
}

function ReturnToWorkSection({ readOnly }: ReturnToWorkSectionProps) {
  const { register, watch, setValue, formState: { errors } } = useFormContext();

  const missedWork = watch('missed_work_beyond_accident');
  const returnedToWork = watch('patient_returned_to_work');
  const modifiedHours = watch('modified_hours');
  const modifiedDuties = watch('modified_duties');
  const dateReturnedToWork = watch('date_returned_to_work');
  const estimatedRtwDate = watch('estimated_rtw_date');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Briefcase className="h-5 w-5" />
          Return to Work
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Missed Work */}
        <div className="space-y-2">
          <Label>Has the worker missed work beyond the day of the accident?</Label>
          <RadioGroup
            value={missedWork || ''}
            onValueChange={(v) =>
              setValue('missed_work_beyond_accident', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="missed_work_yes" />
              <Label htmlFor="missed_work_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="missed_work_no" />
              <Label htmlFor="missed_work_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {/* Returned to Work (conditional) */}
        {missedWork === 'Y' && (
          <>
            <Separator />
            <div className="space-y-2">
              <Label>Has the patient returned to work?</Label>
              <RadioGroup
                value={returnedToWork || ''}
                onValueChange={(v) =>
                  setValue('patient_returned_to_work', v, { shouldValidate: true })
                }
                className="flex gap-6"
                disabled={readOnly}
              >
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="Y" id="returned_yes" />
                  <Label htmlFor="returned_yes" className="font-normal">
                    Yes
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="N" id="returned_no" />
                  <Label htmlFor="returned_no" className="font-normal">
                    No
                  </Label>
                </div>
              </RadioGroup>
            </div>

            {/* Returned = Y */}
            {returnedToWork === 'Y' && (
              <div className="space-y-4 rounded-lg border p-4">
                <div className="space-y-2">
                  <Label>Date Returned to Work</Label>
                  <DatePicker
                    value={
                      dateReturnedToWork ? new Date(dateReturnedToWork) : undefined
                    }
                    onChange={(d) =>
                      setValue(
                        'date_returned_to_work',
                        d ? d.toISOString().split('T')[0] : '',
                        { shouldValidate: true }
                      )
                    }
                    placeholder="Select date..."
                    disabled={readOnly}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Modified hours?</Label>
                  <RadioGroup
                    value={modifiedHours || ''}
                    onValueChange={(v) =>
                      setValue('modified_hours', v, { shouldValidate: true })
                    }
                    className="flex gap-6"
                    disabled={readOnly}
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="Y" id="mod_hours_yes" />
                      <Label htmlFor="mod_hours_yes" className="font-normal">
                        Yes
                      </Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="N" id="mod_hours_no" />
                      <Label htmlFor="mod_hours_no" className="font-normal">
                        No
                      </Label>
                    </div>
                  </RadioGroup>
                </div>

                {modifiedHours === 'Y' && (
                  <div className="space-y-2">
                    <Label htmlFor="hours_capable_per_day">
                      Hours Capable Per Day
                    </Label>
                    <Input
                      id="hours_capable_per_day"
                      type="number"
                      min={0}
                      max={24}
                      className="max-w-[120px]"
                      readOnly={readOnly}
                      {...register('hours_capable_per_day', {
                        valueAsNumber: true,
                      })}
                    />
                  </div>
                )}

                <div className="space-y-2">
                  <Label>Modified duties?</Label>
                  <RadioGroup
                    value={modifiedDuties || ''}
                    onValueChange={(v) =>
                      setValue('modified_duties', v, { shouldValidate: true })
                    }
                    className="flex gap-6"
                    disabled={readOnly}
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="Y" id="mod_duties_yes" />
                      <Label htmlFor="mod_duties_yes" className="font-normal">
                        Yes
                      </Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="N" id="mod_duties_no" />
                      <Label htmlFor="mod_duties_no" className="font-normal">
                        No
                      </Label>
                    </div>
                  </RadioGroup>
                </div>
              </div>
            )}

            {/* Returned = N */}
            {returnedToWork === 'N' && (
              <div className="space-y-4 rounded-lg border p-4">
                <div className="space-y-2">
                  <Label>Estimated Return to Work Date</Label>
                  <DatePicker
                    value={
                      estimatedRtwDate ? new Date(estimatedRtwDate) : undefined
                    }
                    onChange={(d) =>
                      setValue(
                        'estimated_rtw_date',
                        d ? d.toISOString().split('T')[0] : '',
                        { shouldValidate: true }
                      )
                    }
                    placeholder="Select estimated date..."
                    disabled={readOnly}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Reasons for not returning:</Label>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Hospitalized?</Label>
                    <RadioGroup
                      value={watch('rtw_hospitalized') || ''}
                      onValueChange={(v) =>
                        setValue('rtw_hospitalized', v)
                      }
                      className="flex gap-4"
                      disabled={readOnly}
                    >
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="Y" id="hosp_yes" />
                        <Label htmlFor="hosp_yes" className="font-normal">
                          Yes
                        </Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="N" id="hosp_no" />
                        <Label htmlFor="hosp_no" className="font-normal">
                          No
                        </Label>
                      </div>
                    </RadioGroup>
                  </div>

                  <div className="space-y-2">
                    <Label>Self-reported pain?</Label>
                    <RadioGroup
                      value={watch('rtw_self_reported_pain') || ''}
                      onValueChange={(v) =>
                        setValue('rtw_self_reported_pain', v)
                      }
                      className="flex gap-4"
                      disabled={readOnly}
                    >
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="Y" id="pain_yes" />
                        <Label htmlFor="pain_yes" className="font-normal">
                          Yes
                        </Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="N" id="pain_no" />
                        <Label htmlFor="pain_no" className="font-normal">
                          No
                        </Label>
                      </div>
                    </RadioGroup>
                  </div>

                  <div className="space-y-2">
                    <Label>Opioid side effects?</Label>
                    <RadioGroup
                      value={watch('rtw_opioid_side_effects') || ''}
                      onValueChange={(v) =>
                        setValue('rtw_opioid_side_effects', v)
                      }
                      className="flex gap-4"
                      disabled={readOnly}
                    >
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="Y" id="opioid_yes" />
                        <Label htmlFor="opioid_yes" className="font-normal">
                          Yes
                        </Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <RadioGroupItem value="N" id="opioid_no" />
                        <Label htmlFor="opioid_no" className="font-normal">
                          No
                        </Label>
                      </div>
                    </RadioGroup>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="rtw_other_restrictions">
                    Other Restrictions
                  </Label>
                  <Textarea
                    id="rtw_other_restrictions"
                    rows={2}
                    placeholder="Any other restrictions preventing return to work..."
                    readOnly={readOnly}
                    {...register('rtw_other_restrictions')}
                  />
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

export { ReturnToWorkSection };
export type { ReturnToWorkSectionProps };
