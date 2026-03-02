'use client';

import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep6Schema } from '@meritum/shared';
import type { OnboardingStep6 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2 } from 'lucide-react';

interface StepSubmissionPreferencesProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
  onSkip?: () => void;
}

export function StepSubmissionPreferences({ onNext, onBack, onSkip }: StepSubmissionPreferencesProps) {
  const form = useForm<OnboardingStep6>({
    resolver: zodResolver(onboardingStep6Schema),
    defaultValues: {
      ahcip_mode: 'require_approval',
      wcb_mode: 'require_approval',
    },
  });

  const onSubmit = async (data: OnboardingStep6) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Submission Preferences</CardTitle>
        <CardDescription>
          Choose how you want your claims to be processed. Auto-clean will automatically fix common errors before submission. Require approval will flag issues for your review.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="ahcip_mode">AHCIP Submission Mode</Label>
            <Controller
              control={form.control}
              name="ahcip_mode"
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger id="ahcip_mode">
                    <SelectValue placeholder="Select mode" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto_clean">Auto-Clean (automatically fix common errors)</SelectItem>
                    <SelectItem value="require_approval">Require Approval (review before submission)</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {form.formState.errors.ahcip_mode && (
              <p className="text-xs text-destructive">{form.formState.errors.ahcip_mode.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="wcb_mode">WCB Submission Mode</Label>
            <Controller
              control={form.control}
              name="wcb_mode"
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger id="wcb_mode">
                    <SelectValue placeholder="Select mode" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto_clean">Auto-Clean (automatically fix common errors)</SelectItem>
                    <SelectItem value="require_approval">Require Approval (review before submission)</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {form.formState.errors.wcb_mode && (
              <p className="text-xs text-destructive">{form.formState.errors.wcb_mode.message}</p>
            )}
          </div>
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button type="button" variant="outline" onClick={onBack}>
            Back
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={onSkip}>
              Skip
            </Button>
            <Button type="submit" disabled={form.formState.isSubmitting}>
              {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Continue
            </Button>
          </div>
        </CardFooter>
      </form>
    </Card>
  );
}
