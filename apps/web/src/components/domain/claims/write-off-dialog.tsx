'use client';

import * as React from 'react';
import { useForm } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useWriteOffClaim } from '@/hooks/api/use-claims';
import { Loader2 } from 'lucide-react';

// ---------- Types ----------

interface WriteOffDialogProps {
  claimId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onComplete?: () => void;
}

interface WriteOffFormValues {
  reason: string;
}

// ---------- Component ----------

function WriteOffDialog({
  claimId,
  open,
  onOpenChange,
  onComplete,
}: WriteOffDialogProps) {
  const writeOffMutation = useWriteOffClaim();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<WriteOffFormValues>({
    defaultValues: {
      reason: '',
    },
  });

  const onSubmit = async (data: WriteOffFormValues) => {
    await writeOffMutation.mutateAsync({ id: claimId, reason: data.reason });
    reset();
    onOpenChange(false);
    onComplete?.();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Write Off Claim</DialogTitle>
          <DialogDescription>
            This action cannot be undone. The claim will be permanently marked as
            written off and will not be resubmitted.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label
              htmlFor="reason"
              className="after:content-['*'] after:ml-0.5 after:text-destructive"
            >
              Reason for Write-Off
            </Label>
            <Textarea
              id="reason"
              placeholder="Enter the reason for writing off this claim..."
              rows={4}
              {...register('reason', {
                required: 'A reason is required',
                minLength: {
                  value: 1,
                  message: 'Reason must not be empty',
                },
                maxLength: {
                  value: 500,
                  message: 'Reason must be 500 characters or less',
                },
              })}
            />
            {errors.reason && (
              <p className="text-xs text-destructive">{errors.reason.message}</p>
            )}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={writeOffMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={writeOffMutation.isPending}
            >
              {writeOffMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Confirm Write-Off
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export { WriteOffDialog };
export type { WriteOffDialogProps };
