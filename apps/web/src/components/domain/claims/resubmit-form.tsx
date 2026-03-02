'use client';

import * as React from 'react';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useResubmitClaim, useUpdateClaim, type Claim } from '@/hooks/api/use-claims';
import { formatDate } from '@/lib/formatters/date';
import { Loader2, RefreshCw, ArrowRight } from 'lucide-react';

// ---------- Types ----------

interface ResubmitFormProps {
  claim: Claim;
  onSuccess?: () => void;
}

interface ResubmitFormValues {
  date_of_service: string;
  notes: string;
}

// ---------- Component ----------

function ResubmitForm({ claim, onSuccess }: ResubmitFormProps) {
  const updateMutation = useUpdateClaim();
  const resubmitMutation = useResubmitClaim();

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
  } = useForm<ResubmitFormValues>({
    defaultValues: {
      date_of_service: claim.date_of_service,
      notes: '',
    },
  });

  const isLoading = updateMutation.isPending || resubmitMutation.isPending;

  const onSubmit = async (data: ResubmitFormValues) => {
    // If the user changed the date of service, update the claim first
    if (data.date_of_service !== claim.date_of_service) {
      await updateMutation.mutateAsync({
        id: claim.id,
        data: { date_of_service: data.date_of_service },
      });
    }

    await resubmitMutation.mutateAsync(claim.id);
    onSuccess?.();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <RefreshCw className="h-4 w-4" />
          Resubmit Claim
        </CardTitle>
      </CardHeader>
      <form onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          {/* Original values */}
          <div className="rounded-md bg-muted/50 p-3 space-y-2">
            <p className="text-xs font-medium uppercase text-muted-foreground">
              Original Values
            </p>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted-foreground">Claim #:</span>{' '}
                <span className="font-mono">{claim.claim_number}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Date of Service:</span>{' '}
                {formatDate(claim.date_of_service)}
              </div>
              <div>
                <span className="text-muted-foreground">HSC Code(s):</span>{' '}
                {claim.line_items.map((li) => (
                  <Badge key={li.health_service_code} variant="outline" className="ml-1 font-mono">
                    {li.health_service_code}
                  </Badge>
                ))}
              </div>
              <div>
                <span className="text-muted-foreground">Rejection:</span>{' '}
                <Badge variant="destructive">{claim.rejection_code || 'Unknown'}</Badge>
              </div>
            </div>
          </div>

          <Separator />

          {/* Editable overrides */}
          <div className="space-y-3">
            <p className="flex items-center gap-1 text-xs font-medium uppercase text-muted-foreground">
              Corrections <ArrowRight className="h-3 w-3" />
            </p>

            <div className="space-y-2">
              <Label htmlFor="date_of_service">Date of Service</Label>
              <Input
                id="date_of_service"
                type="date"
                {...register('date_of_service', {
                  required: 'Date of service is required',
                })}
              />
              {errors.date_of_service && (
                <p className="text-xs text-destructive">
                  {errors.date_of_service.message}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="notes">Resubmission Notes (optional)</Label>
              <Textarea
                id="notes"
                placeholder="Describe corrections made..."
                rows={3}
                {...register('notes')}
              />
            </div>
          </div>
        </CardContent>
        <CardFooter className="flex justify-end gap-2">
          <Button type="submit" disabled={isLoading}>
            {isLoading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            {isDirty ? 'Update & Resubmit' : 'Resubmit'}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

export { ResubmitForm };
export type { ResubmitFormProps };
