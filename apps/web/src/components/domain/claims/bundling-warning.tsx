'use client';

import { useBundlingCheck } from '@/hooks/api/use-reference';
import { cn } from '@/lib/utils';
import { AlertTriangle, Loader2, CheckCircle2, Info } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export interface BundlingRule {
  codes: string[];
  rule_type: 'inclusive' | 'exclusive' | 'conditional';
  message: string;
  severity: 'error' | 'warning' | 'info';
  suggestion?: string;
}

interface BundlingWarningProps {
  codes: string[];
  className?: string;
}

export function BundlingWarning({ codes, className }: BundlingWarningProps) {
  const { data, isLoading, isError } = useBundlingCheck(codes);
  const warnings = data?.data ?? [];

  // Don't render anything if fewer than 2 codes
  if (codes.length < 2) {
    return null;
  }

  if (isLoading) {
    return (
      <div
        className={cn(
          'flex items-center gap-2 rounded-md border px-3 py-2',
          className
        )}
      >
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        <span className="text-sm text-muted-foreground">
          Checking bundling rules...
        </span>
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className={cn(
          'flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2',
          className
        )}
      >
        <AlertTriangle className="h-4 w-4 text-destructive" />
        <span className="text-sm text-destructive">
          Unable to check bundling rules. Proceed with caution.
        </span>
      </div>
    );
  }

  if (warnings.length === 0) {
    return (
      <div
        className={cn(
          'flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2 dark:border-green-800 dark:bg-green-950',
          className
        )}
      >
        <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
        <span className="text-sm text-green-700 dark:text-green-300">
          No bundling issues detected for selected codes.
        </span>
      </div>
    );
  }

  return (
    <div className={cn('space-y-2', className)}>
      {warnings.map((warning, i) => {
        const Icon =
          warning.severity === 'error'
            ? AlertTriangle
            : warning.severity === 'warning'
              ? AlertTriangle
              : Info;

        const containerClasses = cn(
          'rounded-md border px-3 py-2.5',
          warning.severity === 'error' &&
            'border-destructive/40 bg-destructive/5',
          warning.severity === 'warning' &&
            'border-amber-300 bg-amber-50 dark:border-amber-700 dark:bg-amber-950',
          warning.severity === 'info' &&
            'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950'
        );

        const iconClasses = cn(
          'h-4 w-4 shrink-0 mt-0.5',
          warning.severity === 'error' && 'text-destructive',
          warning.severity === 'warning' &&
            'text-amber-600 dark:text-amber-400',
          warning.severity === 'info' && 'text-blue-600 dark:text-blue-400'
        );

        const textClasses = cn(
          'text-sm',
          warning.severity === 'error' && 'text-destructive',
          warning.severity === 'warning' &&
            'text-amber-800 dark:text-amber-200',
          warning.severity === 'info' && 'text-blue-800 dark:text-blue-200'
        );

        return (
          <div key={i} className={containerClasses}>
            <div className="flex items-start gap-2">
              <Icon className={iconClasses} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <Badge
                    variant={
                      warning.severity === 'error' ? 'destructive' : 'outline'
                    }
                    className="text-xs capitalize"
                  >
                    {warning.rule_type}
                  </Badge>
                  <span className="text-xs text-muted-foreground font-mono">
                    {warning.codes.join(' + ')}
                  </span>
                </div>
                <p className={textClasses}>{warning.message}</p>
                {warning.suggestion && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    Suggestion: {warning.suggestion}
                  </p>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
