'use client';

import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep3Schema } from '@meritum/shared';
import type { OnboardingStep3 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Loader2 } from 'lucide-react';

interface StepBusinessArrangementProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
}

export function StepBusinessArrangement({ onNext, onBack }: StepBusinessArrangementProps) {
  const form = useForm<OnboardingStep3>({
    resolver: zodResolver(onboardingStep3Schema),
    defaultValues: {
      primary_ba_number: '',
      is_pcpcm_enrolled: false,
      pcpcm_ba_number: '',
      ffs_ba_number: '',
    },
  });

  const isPcpcmEnrolled = form.watch('is_pcpcm_enrolled');

  const onSubmit = async (data: OnboardingStep3) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Business Arrangement</CardTitle>
        <CardDescription>
          Configure your business arrangement (BA) numbers. If you participate in PCPCM, provide those details as well.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="primary_ba_number">Primary BA Number</Label>
            <Input
              id="primary_ba_number"
              placeholder="e.g. 12345"
              {...form.register('primary_ba_number')}
            />
            {form.formState.errors.primary_ba_number && (
              <p className="text-xs text-destructive">{form.formState.errors.primary_ba_number.message}</p>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <Controller
              control={form.control}
              name="is_pcpcm_enrolled"
              render={({ field }) => (
                <Checkbox
                  id="is_pcpcm_enrolled"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              )}
            />
            <Label htmlFor="is_pcpcm_enrolled" className="cursor-pointer">
              I am enrolled in PCPCM (Provincial Comprehensive Primary Care Model)
            </Label>
          </div>

          {isPcpcmEnrolled && (
            <>
              <div className="space-y-2">
                <Label htmlFor="pcpcm_ba_number">PCPCM BA Number</Label>
                <Input
                  id="pcpcm_ba_number"
                  placeholder="e.g. 67890"
                  {...form.register('pcpcm_ba_number')}
                />
                {form.formState.errors.pcpcm_ba_number && (
                  <p className="text-xs text-destructive">{form.formState.errors.pcpcm_ba_number.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="ffs_ba_number">Fee-for-Service BA Number</Label>
                <Input
                  id="ffs_ba_number"
                  placeholder="e.g. 11223"
                  {...form.register('ffs_ba_number')}
                />
                {form.formState.errors.ffs_ba_number && (
                  <p className="text-xs text-destructive">{form.formState.errors.ffs_ba_number.message}</p>
                )}
              </div>
            </>
          )}
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button type="button" variant="outline" onClick={onBack}>
            Back
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Continue
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
