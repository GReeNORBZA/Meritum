'use client';

import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SuggestionActions } from './suggestion-actions';
import { cn } from '@/lib/utils';
import { Sparkles, AlertTriangle, Info, BookOpen } from 'lucide-react';
import type { Suggestion, SuggestionTier } from '@/hooks/api/use-intelligence';

// ---------- Tier Configuration ----------

interface TierConfig {
  label: string;
  description: string;
  borderClass: string;
  badgeVariant: 'success' | 'warning' | 'secondary' | 'default';
  icon: React.ReactNode;
}

const TIER_CONFIG: Record<SuggestionTier, TierConfig> = {
  A: {
    label: 'Tier A',
    description: 'High confidence - auto-applicable',
    borderClass: 'border-l-4 border-l-green-500',
    badgeVariant: 'success',
    icon: <Sparkles className="h-4 w-4 text-green-600" />,
  },
  B: {
    label: 'Tier B',
    description: 'Medium confidence - review recommended',
    borderClass: 'border-l-4 border-l-yellow-500',
    badgeVariant: 'warning',
    icon: <AlertTriangle className="h-4 w-4 text-yellow-600" />,
  },
  C: {
    label: 'Tier C',
    description: 'Low confidence - manual review',
    borderClass: 'border-l-4 border-l-gray-400',
    badgeVariant: 'secondary',
    icon: <Info className="h-4 w-4 text-gray-500" />,
  },
  '3': {
    label: 'SOMB Rule',
    description: 'Schedule of Medical Benefits rule change',
    borderClass: 'border-l-4 border-l-blue-500',
    badgeVariant: 'default',
    icon: <BookOpen className="h-4 w-4 text-blue-600" />,
  },
};

// ---------- Types ----------

interface SuggestionCardProps {
  suggestion: Suggestion;
  onAccept?: () => void;
  onDismiss?: () => void;
}

// ---------- Component ----------

function SuggestionCard({ suggestion, onAccept, onDismiss }: SuggestionCardProps) {
  const tierConfig = TIER_CONFIG[suggestion.tier];
  const isResolved = suggestion.status !== 'pending';

  return (
    <Card
      className={cn(
        tierConfig.borderClass,
        isResolved && 'opacity-60',
      )}
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            {tierConfig.icon}
            <Badge variant={tierConfig.badgeVariant}>{tierConfig.label}</Badge>
            <span className="text-xs text-muted-foreground">{tierConfig.description}</span>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="text-xs font-medium text-muted-foreground">Confidence</span>
            <Badge variant="outline" className="font-mono">
              {Math.round(suggestion.confidence_score * 100)}%
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm leading-relaxed">{suggestion.text}</p>

        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-md bg-muted/50 p-2.5">
            <span className="text-xs font-medium text-muted-foreground">Affected Code</span>
            <p className="mt-0.5 font-mono text-sm font-semibold">{suggestion.affected_code}</p>
          </div>
          <div className="rounded-md bg-muted/50 p-2.5">
            <span className="text-xs font-medium text-muted-foreground">Recommended Action</span>
            <p className="mt-0.5 text-sm">{suggestion.recommended_action}</p>
          </div>
        </div>

        {!isResolved && (
          <div className="pt-1">
            <SuggestionActions
              suggestionId={suggestion.id}
              onAccepted={onAccept}
              onDismissed={onDismiss}
            />
          </div>
        )}

        {isResolved && (
          <div className="pt-1">
            <Badge variant={suggestion.status === 'accepted' ? 'success' : 'secondary'}>
              {suggestion.status === 'accepted' ? 'Accepted' : 'Dismissed'}
            </Badge>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export { SuggestionCard, TIER_CONFIG };
export type { SuggestionCardProps };
