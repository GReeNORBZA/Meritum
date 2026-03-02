'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep1Schema } from '@meritum/shared';
import type { OnboardingStep1 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';

interface StepProfessionalIdentityProps {
  onNext: (payload: Record<string, unknown>) => void;
}

export function StepProfessionalIdentity({ onNext }: StepProfessionalIdentityProps) {
  const form = useForm<OnboardingStep1>({
    resolver: zodResolver(onboardingStep1Schema),
    defaultValues: {
      billing_number: '',
      cpsa_number: '',
      legal_first_name: '',
      legal_last_name: '',
    },
  });

  const onSubmit = async (data: OnboardingStep1) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Professional Identity</CardTitle>
        <CardDescription>
          Enter your Alberta Health billing credentials and legal name as they appear on your CPSA registration.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="billing_number">Billing Number (Prac ID)</Label>
            <Input
              id="billing_number"
              placeholder="e.g. 123456"
              {...form.register('billing_number')}
            />
            {form.formState.errors.billing_number && (
              <p className="text-xs text-destructive">{form.formState.errors.billing_number.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="cpsa_number">CPSA Number</Label>
            <Input
              id="cpsa_number"
              placeholder="e.g. 12345"
              {...form.register('cpsa_number')}
            />
            {form.formState.errors.cpsa_number && (
              <p className="text-xs text-destructive">{form.formState.errors.cpsa_number.message}</p>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="legal_first_name">Legal First Name</Label>
              <Input
                id="legal_first_name"
                placeholder="First name"
                {...form.register('legal_first_name')}
              />
              {form.formState.errors.legal_first_name && (
                <p className="text-xs text-destructive">{form.formState.errors.legal_first_name.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="legal_last_name">Legal Last Name</Label>
              <Input
                id="legal_last_name"
                placeholder="Last name"
                {...form.register('legal_last_name')}
              />
              {form.formState.errors.legal_last_name && (
                <p className="text-xs text-destructive">{form.formState.errors.legal_last_name.message}</p>
              )}
            </div>
          </div>
        </CardContent>
        <CardFooter className="flex justify-end">
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Continue
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
