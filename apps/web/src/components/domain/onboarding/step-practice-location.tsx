'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { onboardingStep4Schema } from '@meritum/shared';
import type { OnboardingStep4 } from '@meritum/shared';
import { Card, CardContent, CardFooter, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Loader2 } from 'lucide-react';

interface StepPracticeLocationProps {
  onNext: (payload: Record<string, unknown>) => void;
  onBack?: () => void;
}

export function StepPracticeLocation({ onNext, onBack }: StepPracticeLocationProps) {
  const form = useForm<OnboardingStep4>({
    resolver: zodResolver(onboardingStep4Schema),
    defaultValues: {
      location_name: '',
      functional_centre_code: '',
      facility_number: '',
      address: {
        street: '',
        city: '',
        province: 'AB',
        postal_code: '',
      },
      community_code: '',
    },
  });

  const onSubmit = async (data: OnboardingStep4) => {
    await onNext(data as unknown as Record<string, unknown>);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Practice Location</CardTitle>
        <CardDescription>
          Enter your primary practice location details including functional centre and community codes.
        </CardDescription>
      </CardHeader>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="location_name">Location Name</Label>
            <Input
              id="location_name"
              placeholder="e.g. Main Street Medical Clinic"
              {...form.register('location_name')}
            />
            {form.formState.errors.location_name && (
              <p className="text-xs text-destructive">{form.formState.errors.location_name.message}</p>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="functional_centre_code">Functional Centre Code</Label>
              <Input
                id="functional_centre_code"
                placeholder="e.g. AAAA"
                {...form.register('functional_centre_code')}
              />
              {form.formState.errors.functional_centre_code && (
                <p className="text-xs text-destructive">{form.formState.errors.functional_centre_code.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="facility_number">Facility Number (Optional)</Label>
              <Input
                id="facility_number"
                placeholder="e.g. 12345"
                {...form.register('facility_number')}
              />
              {form.formState.errors.facility_number && (
                <p className="text-xs text-destructive">{form.formState.errors.facility_number.message}</p>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="address.street">Street Address</Label>
            <Input
              id="address.street"
              placeholder="e.g. 123 Main Street"
              {...form.register('address.street')}
            />
            {form.formState.errors.address?.street && (
              <p className="text-xs text-destructive">{form.formState.errors.address.street.message}</p>
            )}
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="address.city">City</Label>
              <Input
                id="address.city"
                placeholder="e.g. Calgary"
                {...form.register('address.city')}
              />
              {form.formState.errors.address?.city && (
                <p className="text-xs text-destructive">{form.formState.errors.address.city.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="address.province">Province</Label>
              <Input
                id="address.province"
                disabled
                {...form.register('address.province')}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="address.postal_code">Postal Code</Label>
              <Input
                id="address.postal_code"
                placeholder="e.g. T2P 1A1"
                {...form.register('address.postal_code')}
              />
              {form.formState.errors.address?.postal_code && (
                <p className="text-xs text-destructive">{form.formState.errors.address.postal_code.message}</p>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="community_code">Community Code</Label>
            <Input
              id="community_code"
              placeholder="e.g. 388"
              {...form.register('community_code')}
            />
            {form.formState.errors.community_code && (
              <p className="text-xs text-destructive">{form.formState.errors.community_code.message}</p>
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
