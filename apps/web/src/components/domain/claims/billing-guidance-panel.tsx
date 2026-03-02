'use client';

import { useHscGuidance } from '@/hooks/api/use-reference';
import { cn } from '@/lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, BookOpen, AlertTriangle, Info } from 'lucide-react';

export interface HscGuidance {
  code: string;
  description: string;
  billing_rules: string[];
  common_rejections: Array<{
    reason: string;
    prevention_tip: string;
  }>;
  documentation_requirements: string[];
  notes: string | null;
  effective_date: string;
  category: string;
}

interface BillingGuidancePanelProps {
  hscCode: string | null;
  className?: string;
}

export function BillingGuidancePanel({
  hscCode,
  className,
}: BillingGuidancePanelProps) {
  const { data, isLoading, isError } = useHscGuidance(hscCode);
  const guidance = data?.data ?? null;

  if (!hscCode) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <BookOpen className="h-4 w-4" />
            Billing Guidance
          </CardTitle>
          <CardDescription>
            Select an HSC code to view billing guidance and rules.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (isLoading) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <BookOpen className="h-4 w-4" />
            Billing Guidance
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-6">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            <span className="ml-2 text-sm text-muted-foreground">
              Loading guidance for {hscCode}...
            </span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError || !guidance) {
    return (
      <Card className={cn('', className)}>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <BookOpen className="h-4 w-4" />
            Billing Guidance
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No guidance available for code{' '}
            <span className="font-mono font-medium">{hscCode}</span>.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn('', className)}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <BookOpen className="h-4 w-4" />
            Billing Guidance
          </CardTitle>
          <Badge variant="outline" className="font-mono">
            {guidance.code}
          </Badge>
        </div>
        <CardDescription>{guidance.description}</CardDescription>
        <div className="flex items-center gap-2 pt-1">
          <Badge variant="secondary" className="text-xs">
            {guidance.category}
          </Badge>
          <span className="text-xs text-muted-foreground">
            Effective: {guidance.effective_date}
          </span>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Billing Rules */}
        {guidance.billing_rules.length > 0 && (
          <section>
            <h4 className="flex items-center gap-1.5 text-sm font-medium mb-2">
              <Info className="h-3.5 w-3.5 text-blue-500" />
              Billing Rules
            </h4>
            <ul className="space-y-1.5">
              {guidance.billing_rules.map((rule, i) => (
                <li
                  key={i}
                  className="text-sm text-muted-foreground flex items-start gap-2"
                >
                  <span className="shrink-0 mt-1.5 h-1 w-1 rounded-full bg-muted-foreground" />
                  {rule}
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* Common Rejections */}
        {guidance.common_rejections.length > 0 && (
          <section>
            <h4 className="flex items-center gap-1.5 text-sm font-medium mb-2">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
              Common Rejections
            </h4>
            <div className="space-y-2">
              {guidance.common_rejections.map((rejection, i) => (
                <div
                  key={i}
                  className="rounded-md border border-amber-200 bg-amber-50 p-2.5 dark:border-amber-800 dark:bg-amber-950"
                >
                  <p className="text-sm font-medium text-amber-900 dark:text-amber-100">
                    {rejection.reason}
                  </p>
                  <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
                    Tip: {rejection.prevention_tip}
                  </p>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Documentation Requirements */}
        {guidance.documentation_requirements.length > 0 && (
          <section>
            <h4 className="text-sm font-medium mb-2">
              Documentation Requirements
            </h4>
            <ul className="space-y-1.5">
              {guidance.documentation_requirements.map((req, i) => (
                <li
                  key={i}
                  className="text-sm text-muted-foreground flex items-start gap-2"
                >
                  <span className="shrink-0 mt-1.5 h-1 w-1 rounded-full bg-muted-foreground" />
                  {req}
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* Additional Notes */}
        {guidance.notes && (
          <section className="rounded-md bg-muted p-3">
            <h4 className="text-sm font-medium mb-1">Notes</h4>
            <p className="text-sm text-muted-foreground">{guidance.notes}</p>
          </section>
        )}
      </CardContent>
    </Card>
  );
}
