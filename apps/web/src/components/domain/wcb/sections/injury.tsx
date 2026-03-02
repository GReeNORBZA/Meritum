'use client';

import { useFormContext, useFieldArray } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { DatePicker } from '@/components/forms/date-picker';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Separator } from '@/components/ui/separator';
import { Plus, Trash2, HeartPulse } from 'lucide-react';

interface InjurySectionProps {
  readOnly?: boolean;
}

const SIDE_OPTIONS = [
  { value: 'L', label: 'Left' },
  { value: 'R', label: 'Right' },
  { value: 'B', label: 'Bilateral' },
] as const;

// ---------- Injury Entry Sub-Component ----------

interface InjuryEntryProps {
  index: number;
  onRemove: () => void;
  readOnly?: boolean;
}

function InjuryEntry({ index, onRemove, readOnly }: InjuryEntryProps) {
  const { register, watch, setValue } = useFormContext();

  const sideValue = watch(`injuries.${index}.side_of_body_code`);

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Injury #{index + 1}</span>
        {!readOnly && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onRemove}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label className="text-xs">Part of Body Code</Label>
          <Input
            maxLength={10}
            placeholder="e.g. HEAD"
            readOnly={readOnly}
            {...register(`injuries.${index}.part_of_body_code`)}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Side</Label>
          <Select
            value={sideValue || ''}
            onValueChange={(v) =>
              setValue(`injuries.${index}.side_of_body_code`, v)
            }
            disabled={readOnly}
          >
            <SelectTrigger>
              <SelectValue placeholder="Side..." />
            </SelectTrigger>
            <SelectContent>
              {SIDE_OPTIONS.map((s) => (
                <SelectItem key={s.value} value={s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Nature of Injury Code</Label>
          <Input
            maxLength={10}
            placeholder="e.g. SPRAIN"
            readOnly={readOnly}
            {...register(`injuries.${index}.nature_of_injury_code`)}
          />
        </div>
      </div>
    </div>
  );
}

// ---------- Injury Section ----------

function InjurySection({ readOnly }: InjurySectionProps) {
  const { control, register, watch, setValue, formState: { errors } } = useFormContext();

  const { fields, append, remove } = useFieldArray({
    control,
    name: 'injuries',
  });

  const dateOfExamination = watch('date_of_examination');
  const diagnosisChanged = watch('diagnosis_changed');
  const priorConditionsFlag = watch('prior_conditions_flag');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <HeartPulse className="h-5 w-5" />
          Injury Assessment
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Examination Info */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Date of Examination</Label>
            <DatePicker
              value={dateOfExamination ? new Date(dateOfExamination) : undefined}
              onChange={(d) =>
                setValue(
                  'date_of_examination',
                  d ? d.toISOString().split('T')[0] : '',
                  { shouldValidate: true }
                )
              }
              placeholder="Select exam date..."
              disabled={readOnly}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="dominant_hand">Dominant Hand</Label>
            <Select
              value={watch('dominant_hand') || ''}
              onValueChange={(v) =>
                setValue('dominant_hand', v, { shouldValidate: true })
              }
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="L">Left</SelectItem>
                <SelectItem value="R">Right</SelectItem>
                <SelectItem value="A">Ambidextrous</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Symptoms & Findings */}
        <div className="space-y-2">
          <Label htmlFor="symptoms">Symptoms</Label>
          <Textarea
            id="symptoms"
            rows={3}
            placeholder="Describe the patient's symptoms..."
            readOnly={readOnly}
            {...register('symptoms')}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="objective_findings">Objective Findings</Label>
          <Textarea
            id="objective_findings"
            rows={3}
            placeholder="Describe objective findings from the examination..."
            readOnly={readOnly}
            {...register('objective_findings')}
          />
        </div>

        {/* Diagnosis */}
        <Separator />

        <div className="space-y-2">
          <Label htmlFor="current_diagnosis">Current Diagnosis</Label>
          <Textarea
            id="current_diagnosis"
            rows={2}
            placeholder="Current diagnosis..."
            readOnly={readOnly}
            {...register('current_diagnosis')}
          />
        </div>

        <div className="space-y-2">
          <Label>Has the diagnosis changed?</Label>
          <RadioGroup
            value={diagnosisChanged || ''}
            onValueChange={(v) =>
              setValue('diagnosis_changed', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="diag_changed_yes" />
              <Label htmlFor="diag_changed_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="diag_changed_no" />
              <Label htmlFor="diag_changed_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {diagnosisChanged === 'Y' && (
          <div className="space-y-2">
            <Label htmlFor="diagnosis_changed_desc">Describe Change</Label>
            <Textarea
              id="diagnosis_changed_desc"
              rows={2}
              placeholder="Describe how the diagnosis has changed..."
              readOnly={readOnly}
              {...register('diagnosis_changed_desc')}
            />
          </div>
        )}

        {/* Diagnostic Codes */}
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="space-y-2">
            <Label htmlFor="diagnostic_code_1">Diagnostic Code 1</Label>
            <Input
              id="diagnostic_code_1"
              maxLength={8}
              placeholder="ICD code"
              className="font-mono"
              readOnly={readOnly}
              {...register('diagnostic_code_1')}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="diagnostic_code_2">Diagnostic Code 2</Label>
            <Input
              id="diagnostic_code_2"
              maxLength={8}
              placeholder="ICD code"
              className="font-mono"
              readOnly={readOnly}
              {...register('diagnostic_code_2')}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="diagnostic_code_3">Diagnostic Code 3</Label>
            <Input
              id="diagnostic_code_3"
              maxLength={8}
              placeholder="ICD code"
              className="font-mono"
              readOnly={readOnly}
              {...register('diagnostic_code_3')}
            />
          </div>
        </div>

        {/* Prior Conditions */}
        <Separator />

        <div className="space-y-2">
          <Label>Prior conditions related to this injury?</Label>
          <RadioGroup
            value={priorConditionsFlag || ''}
            onValueChange={(v) =>
              setValue('prior_conditions_flag', v, { shouldValidate: true })
            }
            className="flex gap-6"
            disabled={readOnly}
          >
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="Y" id="prior_yes" />
              <Label htmlFor="prior_yes" className="font-normal">
                Yes
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="N" id="prior_no" />
              <Label htmlFor="prior_no" className="font-normal">
                No
              </Label>
            </div>
          </RadioGroup>
        </div>

        {priorConditionsFlag === 'Y' && (
          <div className="space-y-2">
            <Label htmlFor="prior_conditions_desc">Describe Prior Conditions</Label>
            <Textarea
              id="prior_conditions_desc"
              rows={2}
              placeholder="Describe prior conditions..."
              readOnly={readOnly}
              {...register('prior_conditions_desc')}
            />
          </div>
        )}

        {/* Injury Entries (Child Table) */}
        <Separator />

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-base font-semibold">Injury Entries</Label>
            {!readOnly && fields.length < 5 && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  append({
                    part_of_body_code: '',
                    side_of_body_code: '',
                    nature_of_injury_code: '',
                  })
                }
              >
                <Plus className="mr-1 h-3 w-3" />
                Add Injury
              </Button>
            )}
          </div>

          {fields.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No injuries added yet. Click "Add Injury" to add a body part and nature of injury.
            </p>
          )}

          {fields.map((field, index) => (
            <InjuryEntry
              key={field.id}
              index={index}
              onRemove={() => remove(index)}
              readOnly={readOnly}
            />
          ))}

          {fields.length >= 5 && (
            <p className="text-xs text-muted-foreground">
              Maximum of 5 injury entries reached.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export { InjurySection, InjuryEntry };
export type { InjurySectionProps };
