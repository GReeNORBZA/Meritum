'use client';

import { useFormContext, useFieldArray } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Plus, Trash2, ClipboardList } from 'lucide-react';

interface TreatmentPlanSectionProps {
  readOnly?: boolean;
}

function TreatmentPlanSection({ readOnly }: TreatmentPlanSectionProps) {
  const { control, register, watch, setValue, formState: { errors } } = useFormContext();

  const narcoticsPrescribed = watch('narcotics_prescribed');
  const caseConfWcbManager = watch('case_conf_wcb_manager');
  const referralRtwProvider = watch('referral_rtw_provider');

  const { fields: prescriptionFields, append: appendPrescription, remove: removePrescription } =
    useFieldArray({ control, name: 'prescriptions' });

  const { fields: consultationFields, append: appendConsultation, remove: removeConsultation } =
    useFieldArray({ control, name: 'consultations' });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ClipboardList className="h-5 w-5" />
          Treatment Plan
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Treatment Plan Text */}
        <div className="space-y-2">
          <Label htmlFor="treatment_plan_text">Treatment Plan</Label>
          <Textarea
            id="treatment_plan_text"
            rows={4}
            placeholder="Describe the treatment plan including recommended treatments, therapies, and follow-up schedule..."
            readOnly={readOnly}
            {...register('treatment_plan_text')}
          />
        </div>

        {/* Narcotics */}
        <Separator />
        <div className="space-y-2">
          <Label>Were narcotics prescribed?</Label>
          <RadioGroup
            value={narcoticsPrescribed || ''}
            onValueChange={(v) =>
              setValue('narcotics_prescribed', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="narcotics_yes" />
              <Label htmlFor="narcotics_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="narcotics_no" />
              <Label htmlFor="narcotics_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {/* Prescriptions (conditional on narcotics=Y) */}
        {narcoticsPrescribed === 'Y' && (
          <div className="space-y-3 rounded-lg border p-4">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-semibold">Prescriptions</Label>
              {!readOnly && prescriptionFields.length < 5 && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    appendPrescription({
                      prescription_name: '',
                      strength: '',
                      daily_intake: '',
                    })
                  }
                >
                  <Plus className="mr-1 h-3 w-3" />
                  Add Prescription
                </Button>
              )}
            </div>

            {prescriptionFields.map((field, index) => (
              <div
                key={field.id}
                className="grid gap-3 rounded-md border p-3 sm:grid-cols-4"
              >
                <div className="space-y-1 sm:col-span-1">
                  <Label className="text-xs">Medication</Label>
                  <Input
                    maxLength={50}
                    placeholder="Name"
                    readOnly={readOnly}
                    {...register(`prescriptions.${index}.prescription_name`)}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Strength</Label>
                  <Input
                    maxLength={30}
                    placeholder="e.g. 5mg"
                    readOnly={readOnly}
                    {...register(`prescriptions.${index}.strength`)}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Daily Intake</Label>
                  <Input
                    maxLength={30}
                    placeholder="e.g. 2x/day"
                    readOnly={readOnly}
                    {...register(`prescriptions.${index}.daily_intake`)}
                  />
                </div>
                {!readOnly && (
                  <div className="flex items-end">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => removePrescription(index)}
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Case Conference */}
        <Separator />
        <div className="space-y-2">
          <Label>Case conference with WCB Case Manager?</Label>
          <RadioGroup
            value={caseConfWcbManager || ''}
            onValueChange={(v) =>
              setValue('case_conf_wcb_manager', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="case_conf_yes" />
              <Label htmlFor="case_conf_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="case_conf_no" />
              <Label htmlFor="case_conf_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {/* Referral to RTW Provider */}
        <div className="space-y-2">
          <Label>Referral to Return-to-Work provider?</Label>
          <RadioGroup
            value={referralRtwProvider || ''}
            onValueChange={(v) =>
              setValue('referral_rtw_provider', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="referral_rtw_yes" />
              <Label htmlFor="referral_rtw_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="referral_rtw_no" />
              <Label htmlFor="referral_rtw_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {/* Consultations */}
        <Separator />
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-semibold">Consultations / Referrals</Label>
            {!readOnly && consultationFields.length < 5 && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  appendConsultation({
                    category: '',
                    type_code: '',
                    details: '',
                    expedite_requested: '',
                  })
                }
              >
                <Plus className="mr-1 h-3 w-3" />
                Add Consultation
              </Button>
            )}
          </div>

          {consultationFields.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No consultations added. Click "Add Consultation" if applicable.
            </p>
          )}

          {consultationFields.map((field, index) => (
            <div
              key={field.id}
              className="grid gap-3 rounded-md border p-3 sm:grid-cols-2"
            >
              <div className="space-y-1">
                <Label className="text-xs">Category</Label>
                <Select
                  value={watch(`consultations.${index}.category`) || ''}
                  onValueChange={(v) =>
                    setValue(`consultations.${index}.category`, v)
                  }
                  disabled={readOnly}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="CONREF">Consultation/Referral</SelectItem>
                    <SelectItem value="INVE">Investigation</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Type Code</Label>
                <Input
                  maxLength={10}
                  placeholder="Type code"
                  readOnly={readOnly}
                  {...register(`consultations.${index}.type_code`)}
                />
              </div>
              <div className="space-y-1 sm:col-span-2">
                <Label className="text-xs">Details</Label>
                <Input
                  maxLength={50}
                  placeholder="Consultation details"
                  readOnly={readOnly}
                  {...register(`consultations.${index}.details`)}
                />
              </div>
              {!readOnly && (
                <div className="flex items-end sm:col-span-2">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removeConsultation(index)}
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="mr-1 h-4 w-4" />
                    Remove
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export { TreatmentPlanSection };
export type { TreatmentPlanSectionProps };
