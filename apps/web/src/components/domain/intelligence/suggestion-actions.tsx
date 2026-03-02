'use client';

import { Button } from '@/components/ui/button';
import { useAcceptSuggestion, useDismissSuggestion } from '@/hooks/api/use-intelligence';
import { Loader2, Check, X } from 'lucide-react';

// ---------- Types ----------

interface SuggestionActionsProps {
  suggestionId: string;
  onAccepted?: () => void;
  onDismissed?: () => void;
}

// ---------- Component ----------

function SuggestionActions({ suggestionId, onAccepted, onDismissed }: SuggestionActionsProps) {
  const acceptMutation = useAcceptSuggestion();
  const dismissMutation = useDismissSuggestion();

  const isLoading = acceptMutation.isPending || dismissMutation.isPending;

  const handleAccept = () => {
    acceptMutation.mutate(suggestionId, {
      onSuccess: () => {
        onAccepted?.();
      },
    });
  };

  const handleDismiss = () => {
    dismissMutation.mutate(suggestionId, {
      onSuccess: () => {
        onDismissed?.();
      },
    });
  };

  return (
    <div className="flex items-center gap-2">
      <Button
        variant="default"
        size="sm"
        onClick={handleAccept}
        disabled={isLoading}
      >
        {acceptMutation.isPending ? (
          <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
        ) : (
          <Check className="mr-1.5 h-3.5 w-3.5" />
        )}
        Accept
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={handleDismiss}
        disabled={isLoading}
      >
        {dismissMutation.isPending ? (
          <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
        ) : (
          <X className="mr-1.5 h-3.5 w-3.5" />
        )}
        Dismiss
      </Button>
    </div>
  );
}

export { SuggestionActions };
export type { SuggestionActionsProps };
