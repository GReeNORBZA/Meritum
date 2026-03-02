'use client';

import { useFormContext } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DatePicker } from '@/components/forms/date-picker';
import { Separator } from '@/components/ui/separator';
import { Activity } from 'lucide-react';

interface OisFieldsSectionProps {
  readOnly?: boolean;
}

const GRASP_LEVELS = [
  { value: 'ABLE', label: 'Able' },
  { value: 'UNABLE', label: 'Unable' },
  { value: 'LIMITED', label: 'Limited' },
] as const;

const LIFT_LEVELS = [
  { value: 'ABLE', label: 'Able' },
  { value: 'UNABLE', label: 'Unable' },
  { value: 'LIMITEDTO', label: 'Limited To' },
] as const;

const FITNESS_LEVELS = [
  { value: 'FIT', label: 'Fit for Work' },
  { value: 'NOTFIT', label: 'Not Fit for Work' },
] as const;

const RTW_LEVELS = [
  { value: 'PREINJURY', label: 'Pre-Injury Level' },
  { value: 'LIMITATION', label: 'With Limitations' },
] as const;

// ---------- Y/N Field Helper ----------

function YNField({
  name,
  label,
  readOnly,
}: {
  name: string;
  label: string;
  readOnly?: boolean;
}) {
  const { watch, setValue } = useFormContext();
  const val = watch(name);

  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      <RadioGroup
        value={val || ''}
        onValueChange={(v) => setValue(name, v)}
        className="flex gap-4"
        disabled={readOnly}
      >
        <div className="flex items-center space-x-1">
          <RadioGroupItem value="Y" id={`${name}_y`} />
          <Label htmlFor={`${name}_y`} className="text-xs font-normal">Y</Label>
        </div>
        <div className="flex items-center space-x-1">
          <RadioGroupItem value="N" id={`${name}_n`} />
          <Label htmlFor={`${name}_n`} className="text-xs font-normal">N</Label>
        </div>
      </RadioGroup>
    </div>
  );
}

// ---------- Grasp Panel ----------

function GraspPanel({
  side,
  readOnly,
}: {
  side: 'right' | 'left';
  readOnly?: boolean;
}) {
  const { watch, setValue } = useFormContext();
  const prefix = `grasp_${side}`;
  const level = watch(`${prefix}_level`);

  return (
    <div className="space-y-3 rounded-lg border p-3">
      <Label className="text-sm font-medium capitalize">{side} Hand Grasping</Label>
      <div className="space-y-1">
        <Label className="text-xs">Level</Label>
        <Select
          value={level || ''}
          onValueChange={(v) => setValue(`${prefix}_level`, v)}
          disabled={readOnly}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select..." />
          </SelectTrigger>
          <SelectContent>
            {GRASP_LEVELS.map((g) => (
              <SelectItem key={g.value} value={g.value}>
                {g.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <YNField name={`${prefix}_prolonged`} label="Prolonged" readOnly={readOnly} />
        <YNField name={`${prefix}_repetitive`} label="Repetitive" readOnly={readOnly} />
        <YNField name={`${prefix}_vibration`} label="Vibration" readOnly={readOnly} />
        <YNField name={`${prefix}_specify`} label="Specify" readOnly={readOnly} />
      </div>
    </div>
  );
}

// ---------- Main Section ----------

function OisFieldsSection({ readOnly }: OisFieldsSectionProps) {
  const { register, watch, setValue } = useFormContext();

  const environmentRestricted = watch('environment_restricted');
  const oisFollowupRequired = watch('ois_followup_required');
  const oisFitnessAssessment = watch('ois_fitness_assessment');
  const oisEmpModifiedWorkRequired = watch('ois_emp_modified_work_required');
  const oisHasFamilyPhysician = watch('ois_has_family_physician');

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" />
          OIS Assessment (Occupational Injury Service)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Hand Grasping */}
        <Label className="text-base font-semibold">Hand Grasping Assessment</Label>
        <div className="grid gap-4 sm:grid-cols-2">
          <GraspPanel side="right" readOnly={readOnly} />
          <GraspPanel side="left" readOnly={readOnly} />
        </div>

        {/* Zone-Specific Lifting */}
        <Separator />
        <Label className="text-base font-semibold">Zone-Specific Lifting</Label>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            { key: 'floor_to_waist', label: 'Floor to Waist' },
            { key: 'waist_to_shoulder', label: 'Waist to Shoulder' },
            { key: 'above_shoulder', label: 'Above Shoulder' },
          ].map(({ key, label }) => (
            <div key={key} className="space-y-2 rounded-lg border p-3">
              <Label className="text-xs font-medium">{label}</Label>
              <div className="space-y-1">
                <Label className="text-xs">Level</Label>
                <Select
                  value={watch(`lift_${key}`) || ''}
                  onValueChange={(v) => setValue(`lift_${key}`, v)}
                  disabled={readOnly}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select..." />
                  </SelectTrigger>
                  <SelectContent>
                    {LIFT_LEVELS.map((l) => (
                      <SelectItem key={l.value} value={l.value}>
                        {l.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Max Weight</Label>
                <Input
                  maxLength={10}
                  placeholder="e.g. 10kg"
                  readOnly={readOnly}
                  {...register(`lift_${key}_max`)}
                />
              </div>
            </div>
          ))}
        </div>

        {/* Directional Reaching */}
        <Separator />
        <Label className="text-base font-semibold">Directional Reaching</Label>
        <div className="grid gap-4 sm:grid-cols-2">
          {[
            { key: 'reach_above_right_shoulder', label: 'Above Right Shoulder' },
            { key: 'reach_below_right_shoulder', label: 'Below Right Shoulder' },
            { key: 'reach_above_left_shoulder', label: 'Above Left Shoulder' },
            { key: 'reach_below_left_shoulder', label: 'Below Left Shoulder' },
          ].map(({ key, label }) => (
            <div key={key} className="space-y-1">
              <Label className="text-xs">{label}</Label>
              <Select
                value={watch(key) || ''}
                onValueChange={(v) => setValue(key, v)}
                disabled={readOnly}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  {LIFT_LEVELS.map((l) => (
                    <SelectItem key={l.value} value={l.value}>
                      {l.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
        </div>

        {/* Environmental Restrictions */}
        <Separator />
        <div className="space-y-3">
          <YNField
            name="environment_restricted"
            label="Environmental Restrictions?"
            readOnly={readOnly}
          />

          {environmentRestricted === 'Y' && (
            <div className="grid grid-cols-2 gap-2 rounded-lg border p-3 sm:grid-cols-4">
              {[
                { key: 'env_cold', label: 'Cold' },
                { key: 'env_hot', label: 'Hot' },
                { key: 'env_wet', label: 'Wet' },
                { key: 'env_dry', label: 'Dry' },
                { key: 'env_dust', label: 'Dust' },
                { key: 'env_lighting', label: 'Lighting' },
                { key: 'env_noise', label: 'Noise' },
              ].map(({ key, label }) => (
                <YNField key={key} name={key} label={label} readOnly={readOnly} />
              ))}
            </div>
          )}
        </div>

        {/* Fitness Assessment */}
        <Separator />
        <Label className="text-base font-semibold">Assessment Summary</Label>

        <div className="grid gap-4 sm:grid-cols-2">
          <YNField
            name="ois_reviewed_with_patient"
            label="Reviewed with Patient?"
            readOnly={readOnly}
          />

          <div className="space-y-1">
            <Label className="text-xs">Fitness Assessment</Label>
            <Select
              value={oisFitnessAssessment || ''}
              onValueChange={(v) => setValue('ois_fitness_assessment', v)}
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select..." />
              </SelectTrigger>
              <SelectContent>
                {FITNESS_LEVELS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1">
            <Label className="text-xs">RTW Level</Label>
            <Select
              value={watch('ois_rtw_level') || ''}
              onValueChange={(v) => setValue('ois_rtw_level', v)}
              disabled={readOnly}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select..." />
              </SelectTrigger>
              <SelectContent>
                {RTW_LEVELS.map((r) => (
                  <SelectItem key={r.value} value={r.value}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1">
            <Label className="text-xs">Estimated RTW Date</Label>
            <DatePicker
              value={
                watch('ois_estimated_rtw_date')
                  ? new Date(watch('ois_estimated_rtw_date'))
                  : undefined
              }
              onChange={(d) =>
                setValue(
                  'ois_estimated_rtw_date',
                  d ? d.toISOString().split('T')[0] : ''
                )
              }
              placeholder="Select date..."
              disabled={readOnly}
            />
          </div>
        </div>

        {/* Follow-up */}
        <div className="space-y-3">
          <YNField
            name="ois_followup_required"
            label="Follow-up Required?"
            readOnly={readOnly}
          />
          {oisFollowupRequired === 'Y' && (
            <div className="space-y-1">
              <Label className="text-xs">Follow-up Date</Label>
              <DatePicker
                value={
                  watch('ois_followup_date')
                    ? new Date(watch('ois_followup_date'))
                    : undefined
                }
                onChange={(d) =>
                  setValue(
                    'ois_followup_date',
                    d ? d.toISOString().split('T')[0] : ''
                  )
                }
                placeholder="Select date..."
                disabled={readOnly}
              />
            </div>
          )}
        </div>

        {/* Employer Modified Work */}
        <Separator />
        <div className="space-y-3">
          <YNField
            name="ois_emp_modified_work_required"
            label="Modified Work Required from Employer?"
            readOnly={readOnly}
          />
          {oisEmpModifiedWorkRequired === 'Y' && (
            <div className="space-y-2 rounded-lg border p-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label className="text-xs">Modified Work From</Label>
                  <DatePicker
                    value={
                      watch('ois_emp_modified_from_date')
                        ? new Date(watch('ois_emp_modified_from_date'))
                        : undefined
                    }
                    onChange={(d) =>
                      setValue(
                        'ois_emp_modified_from_date',
                        d ? d.toISOString().split('T')[0] : ''
                      )
                    }
                    disabled={readOnly}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Modified Work To</Label>
                  <DatePicker
                    value={
                      watch('ois_emp_modified_to_date')
                        ? new Date(watch('ois_emp_modified_to_date'))
                        : undefined
                    }
                    onChange={(d) =>
                      setValue(
                        'ois_emp_modified_to_date',
                        d ? d.toISOString().split('T')[0] : ''
                      )
                    }
                    disabled={readOnly}
                  />
                </div>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Employer Comments</Label>
                <Textarea
                  rows={2}
                  readOnly={readOnly}
                  {...register('ois_emp_comments')}
                />
              </div>
            </div>
          )}
        </div>

        {/* Family Physician */}
        <Separator />
        <div className="space-y-3">
          <YNField
            name="ois_has_family_physician"
            label="Has Family Physician?"
            readOnly={readOnly}
          />
          {oisHasFamilyPhysician === 'Y' && (
            <div className="space-y-2 rounded-lg border p-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label className="text-xs">Family Physician Name</Label>
                  <Input
                    maxLength={50}
                    readOnly={readOnly}
                    {...register('ois_family_physician_name')}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Phone</Label>
                  <Input
                    type="tel"
                    maxLength={24}
                    readOnly={readOnly}
                    {...register('ois_family_physician_phone')}
                  />
                </div>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Treatment Plan</Label>
                <Textarea
                  rows={2}
                  readOnly={readOnly}
                  {...register('ois_family_physician_plan')}
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Comments</Label>
                <Textarea
                  rows={2}
                  readOnly={readOnly}
                  {...register('ois_family_physician_comments')}
                />
              </div>
            </div>
          )}
        </div>

        {/* Worker Comments */}
        <Separator />
        <div className="space-y-2">
          <Label htmlFor="ois_worker_comments">Worker Comments</Label>
          <Textarea
            id="ois_worker_comments"
            rows={3}
            placeholder="Additional worker comments..."
            readOnly={readOnly}
            {...register('ois_worker_comments')}
          />
        </div>
      </CardContent>
    </Card>
  );
}

export { OisFieldsSection };
export type { OisFieldsSectionProps };
