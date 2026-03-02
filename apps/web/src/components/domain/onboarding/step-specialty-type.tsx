'use client';

import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep2Schema } from '@meritum/shared';
import type { OnboardingStep2 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2 } from 'lucide-react';

interface StepSpecialtyTypeProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
}

export function StepSpecialtyType({ onNext, onBack }: StepSpecialtyTypeProps) {
  const form = useForm<OnboardingStep2>({
    resolver: zodResolver(onboardingStep2Schema),
    defaultValues: {
      specialty_code: '',
      physician_type: undefined,
    },
  });

  const onSubmit = async (data: OnboardingStep2) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Specialty & Type</CardTitle>
        <CardDescription>
          Specify your medical specialty code and physician type for billing categorization.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="specialty_code">Specialty Code</Label>
            <Input
              id="specialty_code"
              placeholder="e.g. 01"
              {...form.register('specialty_code')}
            />
            {form.formState.errors.specialty_code && (
              <p className="text-xs text-destructive">{form.formState.errors.specialty_code.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="physician_type">Physician Type</Label>
            <Controller
              control={form.control}
              name="physician_type"
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger id="physician_type">
                    <SelectValue placeholder="Select physician type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="GP">General Practitioner</SelectItem>
                    <SelectItem value="Specialist">Specialist</SelectItem>
                    <SelectItem value="Locum">Locum</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
            {form.formState.errors.physician_type && (
              <p className="text-xs text-destructive">{form.formState.errors.physician_type.message}</p>
            )}
          </div>
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
