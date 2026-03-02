'use client';

import * as React from 'react';
import { Button } from '@/components/ui/button';
import {
  useValidateClaim,
  useQueueClaim,
  useUnqueueClaim,
  useResubmitClaim,
  type Claim,
} from '@/hooks/api/use-claims';
import { Loader2, CheckCircle, Send, Undo2, RefreshCw } from 'lucide-react';

// ---------- Types ----------

interface ClaimStateActionsProps {
  claim: Claim;
  onWriteOff?: () => void;
}

// ---------- Component ----------

function ClaimStateActions({ claim, onWriteOff }: ClaimStateActionsProps) {
  const validateMutation = useValidateClaim();
  const queueMutation = useQueueClaim();
  const unqueueMutation = useUnqueueClaim();
  const resubmitMutation = useResubmitClaim();

  const isAnyLoading =
    validateMutation.isPending ||
    queueMutation.isPending ||
    unqueueMutation.isPending ||
    resubmitMutation.isPending;

  const handleValidate = () => {
    validateMutation.mutate(claim.id);
  };

  const handleQueue = () => {
    queueMutation.mutate(claim.id);
  };

  const handleUnqueue = () => {
    unqueueMutation.mutate(claim.id);
  };

  const handleResubmit = () => {
    resubmitMutation.mutate(claim.id);
  };

  switch (claim.state) {
    case 'DRAFT':
      return (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={handleValidate}
            disabled={isAnyLoading}
          >
            {validateMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <CheckCircle className="mr-2 h-4 w-4" />
            )}
            Validate
          </Button>
          <Button onClick={handleQueue} disabled={isAnyLoading}>
            {queueMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            Queue for Submission
          </Button>
        </div>
      );

    case 'VALIDATED':
      return (
        <div className="flex flex-wrap gap-2">
          <Button onClick={handleQueue} disabled={isAnyLoading}>
            {queueMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Send className="mr-2 h-4 w-4" />
            )}
            Queue for Submission
          </Button>
        </div>
      );

    case 'QUEUED':
      return (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={handleUnqueue}
            disabled={isAnyLoading}
          >
            {unqueueMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Undo2 className="mr-2 h-4 w-4" />
            )}
            Unqueue
          </Button>
        </div>
      );

    case 'SUBMITTED':
      return (
        <div className="text-sm text-muted-foreground">
          Claim has been submitted. Awaiting assessment from AHCIP.
        </div>
      );

    case 'REJECTED':
      return (
        <div className="flex flex-wrap gap-2">
          <Button onClick={handleResubmit} disabled={isAnyLoading}>
            {resubmitMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            Resubmit
          </Button>
          {onWriteOff && (
            <Button
              variant="outline"
              onClick={onWriteOff}
              disabled={isAnyLoading}
            >
              Write Off
            </Button>
          )}
        </div>
      );

    case 'PAID':
    case 'ACCEPTED':
    case 'ASSESSED':
      return (
        <div className="text-sm text-muted-foreground">
          Claim has been processed. No further actions available.
        </div>
      );

    case 'WRITTEN_OFF':
      return (
        <div className="text-sm text-muted-foreground">
          Claim has been written off.
        </div>
      );

    default:
      return null;
  }
}

export { ClaimStateActions };
export type { ClaimStateActionsProps };
