'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep5Schema } from '@meritum/shared';
import type { OnboardingStep5 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';

interface StepWcbConfigProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
  onSkip?: () => void;
}

export function StepWcbConfig({ onNext, onBack, onSkip }: StepWcbConfigProps) {
  const form = useForm<OnboardingStep5>({
    resolver: zodResolver(onboardingStep5Schema),
    defaultValues: {
      contract_id: '',
      role: '',
      skill_code: '',
    },
  });

  const onSubmit = async (data: OnboardingStep5) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>WCB Configuration</CardTitle>
        <CardDescription>
          If you submit WCB (Workers&apos; Compensation Board) claims, provide your contract details below. You can skip this step and configure it later.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="contract_id">WCB Contract ID</Label>
            <Input
              id="contract_id"
              placeholder="e.g. WCB-12345"
              {...form.register('contract_id')}
            />
            {form.formState.errors.contract_id && (
              <p className="text-xs text-destructive">{form.formState.errors.contract_id.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="role">Role</Label>
            <Input
              id="role"
              placeholder="e.g. Attending Physician"
              {...form.register('role')}
            />
            {form.formState.errors.role && (
              <p className="text-xs text-destructive">{form.formState.errors.role.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="skill_code">Skill Code</Label>
            <Input
              id="skill_code"
              placeholder="e.g. MD"
              {...form.register('skill_code')}
            />
            {form.formState.errors.skill_code && (
              <p className="text-xs text-destructive">{form.formState.errors.skill_code.message}</p>
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
