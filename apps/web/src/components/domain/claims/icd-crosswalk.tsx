'use client';

import { useState } from 'react';
import { useIcdCrosswalk } from '@/hooks/api/use-reference';
import { cn } from '@/lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Loader2, ArrowRight, Check, ArrowLeftRight } from 'lucide-react';

export interface CrosswalkMapping {
  icd9_code: string;
  icd9_description: string;
  match_confidence: 'exact' | 'approximate' | 'partial';
  notes?: string;
}

interface IcdCrosswalkProps {
  icd10Code: string;
  onResolve: (icd9Code: string) => void;
  className?: string;
}

export function IcdCrosswalk({
  icd10Code,
  onResolve,
  className,
}: IcdCrosswalkProps) {
  const { data, isLoading, isError } = useIcdCrosswalk(icd10Code);
  const mappings = data?.data ?? [];
  const [selectedCode, setSelectedCode] = useState<string | null>(null);

  if (!icd10Code) {
    return null;
  }

  if (isLoading) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-4 w-4" />
            ICD Crosswalk
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-4">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            <span className="ml-2 text-sm text-muted-foreground">
              Finding ICD-9 mappings for {icd10Code}...
            </span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-4 w-4" />
            ICD Crosswalk
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-destructive">
            Failed to look up crosswalk mappings for{' '}
            <span className="font-mono">{icd10Code}</span>.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (mappings.length === 0) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-4 w-4" />
            ICD Crosswalk
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No ICD-9 mappings found for{' '}
            <span className="font-mono font-medium">{icd10Code}</span>.
          </p>
        </CardContent>
      </Card>
    );
  }

  // If there's only one exact match, auto-select it
  const autoResolved =
    mappings.length === 1 && mappings[0].match_confidence === 'exact';

  const confidenceBadge = (confidence: CrosswalkMapping['match_confidence']) => {
    const variants: Record<
      string,
      { variant: 'default' | 'secondary' | 'outline'; label: string }
    > = {
      exact: { variant: 'default', label: 'Exact' },
      approximate: { variant: 'secondary', label: 'Approximate' },
      partial: { variant: 'outline', label: 'Partial' },
    };
    const config = variants[confidence] ?? variants.partial;
    return (
      <Badge variant={config.variant} className="text-xs">
        {config.label}
      </Badge>
    );
  };

  return (
    <Card className={cn('', className)}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ArrowLeftRight className="h-4 w-4" />
          ICD Crosswalk
        </CardTitle>
        <CardDescription>
          <span className="font-mono font-medium">{icd10Code}</span>
          <ArrowRight className="inline mx-1.5 h-3 w-3" />
          {autoResolved
            ? 'Single exact match found'
            : `${mappings.length} possible ICD-9 mapping${mappings.length !== 1 ? 's' : ''} found. Select one to continue.`}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {mappings.map((mapping) => {
          const isSelected = selectedCode === mapping.icd9_code;

          return (
            <button
              key={mapping.icd9_code}
              type="button"
              onClick={() => setSelectedCode(mapping.icd9_code)}
              className={cn(
                'w-full rounded-md border p-3 text-left transition-colors',
                'hover:bg-accent focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1',
                isSelected && 'border-primary bg-primary/5 ring-1 ring-primary'
              )}
            >
              <div className="flex items-start justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-semibold text-sm">
                      {mapping.icd9_code}
                    </span>
                    {confidenceBadge(mapping.match_confidence)}
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {mapping.icd9_description}
                  </p>
                  {mapping.notes && (
                    <p className="mt-1 text-xs text-muted-foreground/70 italic">
                      {mapping.notes}
                    </p>
                  )}
                </div>
                {isSelected && (
                  <Check className="h-5 w-5 shrink-0 text-primary ml-2" />
                )}
              </div>
            </button>
          );
        })}

        <div className="pt-2">
          <Button
            onClick={() => {
              const code = selectedCode ?? (autoResolved ? mappings[0].icd9_code : null);
              if (code) {
                onResolve(code);
              }
            }}
            disabled={!selectedCode && !autoResolved}
            className="w-full"
            size="sm"
          >
            {autoResolved && !selectedCode
              ? `Use ${mappings[0].icd9_code}`
              : selectedCode
                ? `Use ${selectedCode}`
                : 'Select a mapping'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
