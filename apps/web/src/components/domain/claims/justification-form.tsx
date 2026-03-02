'use client';

import * as React from 'react';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { api } from '@/lib/api/client';
import type { ApiResponse } from '@/lib/api/client';
import { Loader2, FileText } from 'lucide-react';

// ---------- Constants ----------

const JUSTIFICATION_SCENARIOS = {
  UNLISTED_PROCEDURE: {
    label: 'Unlisted Procedure',
    description: 'Justify the use of an unlisted procedure code.',
    placeholder:
      'Describe the procedure performed, why no specific code exists, and the complexity involved...',
  },
  ADDITIONAL_COMPENSATION: {
    label: 'Additional Compensation',
    description: 'Justify a request for additional compensation beyond the standard fee.',
    placeholder:
      'Describe the additional time, complexity, or resources required beyond the standard procedure...',
  },
  PRE_OP_CONSERVATIVE: {
    label: 'Pre-Operative Conservative Treatment',
    description: 'Justify that conservative treatment was attempted before surgery.',
    placeholder:
      'Describe the conservative treatments attempted, duration, and why surgical intervention is now required...',
  },
  POST_OP_COMPLICATION: {
    label: 'Post-Operative Complication',
    description: 'Justify treatment for a post-operative complication.',
    placeholder:
      'Describe the complication, its relationship to the original procedure, and the treatment provided...',
  },
  WCB_NARRATIVE: {
    label: 'WCB Narrative',
    description: 'Provide a narrative for WCB claims.',
    placeholder:
      'Describe the injury, mechanism, workplace relationship, and treatment provided...',
  },
} as const;

type Scenario = keyof typeof JUSTIFICATION_SCENARIOS;

// ---------- Types ----------

interface JustificationFormProps {
  claimId: string;
  initialScenario?: Scenario;
  onSuccess?: () => void;
  className?: string;
}

interface JustificationFormValues {
  scenario: Scenario;
  justification_text: string;
}

// ---------- Component ----------

function JustificationForm({
  claimId,
  initialScenario,
  onSuccess,
  className,
}: JustificationFormProps) {
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [submitError, setSubmitError] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<JustificationFormValues>({
    defaultValues: {
      scenario: initialScenario || 'UNLISTED_PROCEDURE',
      justification_text: '',
    },
  });

  const selectedScenario = watch('scenario');
  const scenarioConfig = JUSTIFICATION_SCENARIOS[selectedScenario];

  const onSubmit = async (data: JustificationFormValues) => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await api.post<ApiResponse<unknown>>('/api/v1/claims/justifications', {
        claim_id: claimId,
        scenario: data.scenario,
        justification_text: data.justification_text,
      });
      onSuccess?.();
    } catch (err) {
      setSubmitError(
        err instanceof Error ? err.message : 'Failed to save justification'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const textLength = watch('justification_text')?.length ?? 0;

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <FileText className="h-4 w-4" />
          Justification
        </CardTitle>
      </CardHeader>
      <form onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label
              htmlFor="scenario"
              className="after:content-['*'] after:ml-0.5 after:text-destructive"
            >
              Scenario
            </Label>
            <Select
              value={selectedScenario}
              onValueChange={(val) => setValue('scenario', val as Scenario)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select scenario..." />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(JUSTIFICATION_SCENARIOS) as [Scenario, (typeof JUSTIFICATION_SCENARIOS)[Scenario]][]).map(
                  ([key, config]) => (
                    <SelectItem key={key} value={key}>
                      {config.label}
                    </SelectItem>
                  )
                )}
              </SelectContent>
            </Select>
            {scenarioConfig && (
              <p className="text-xs text-muted-foreground">
                {scenarioConfig.description}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label
              htmlFor="justification_text"
              className="after:content-['*'] after:ml-0.5 after:text-destructive"
            >
              Justification Text
            </Label>
            <Textarea
              id="justification_text"
              placeholder={scenarioConfig?.placeholder}
              rows={6}
              {...register('justification_text', {
                required: 'Justification text is required',
                minLength: {
                  value: 10,
                  message: 'Justification must be at least 10 characters',
                },
                maxLength: {
                  value: 5000,
                  message: 'Justification must be 5000 characters or less',
                },
              })}
            />
            <div className="flex items-center justify-between">
              {errors.justification_text ? (
                <p className="text-xs text-destructive">
                  {errors.justification_text.message}
                </p>
              ) : (
                <span />
              )}
              <span className="text-xs text-muted-foreground">
                {textLength}/5000
              </span>
            </div>
          </div>

          {submitError && (
            <p className="text-sm text-destructive">{submitError}</p>
          )}
        </CardContent>
        <CardFooter className="flex justify-end">
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Save Justification
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

export { JustificationForm };
export type { JustificationFormProps };
