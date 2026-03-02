'use client';

import { useSuggestions } from '@/hooks/api/use-intelligence';
import { SuggestionCard } from './suggestion-card';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { Sparkles } from 'lucide-react';

// ---------- Types ----------

interface SuggestionPanelProps {
  claimId: string;
}

// ---------- Component ----------

function SuggestionPanel({ claimId }: SuggestionPanelProps) {
  const { data, isLoading, isError } = useSuggestions(claimId);

  const suggestions = data?.data ?? [];
  const pendingCount = suggestions.filter((s) => s.status === 'pending').length;

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            AI Suggestions
          </CardTitle>
          <CardDescription>Analyzing claim for optimization opportunities...</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-32 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            AI Suggestions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Unable to load suggestions. Please try again later.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (suggestions.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            AI Suggestions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No suggestions for this claim. The claim looks good as-is.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              AI Suggestions
            </CardTitle>
            <CardDescription>
              Review AI-powered suggestions to optimize this claim
            </CardDescription>
          </div>
          {pendingCount > 0 && (
            <Badge variant="default">{pendingCount} pending</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {suggestions.map((suggestion) => (
          <SuggestionCard
            key={suggestion.id}
            suggestion={suggestion}
          />
        ))}
      </CardContent>
    </Card>
  );
}

export { SuggestionPanel };
export type { SuggestionPanelProps };
