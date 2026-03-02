'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { formatCurrency } from '@/lib/formatters/currency';
import { DollarSign, TrendingUp } from 'lucide-react';
import type { FeeCalculation } from '@/hooks/api/use-claims';

// ---------- Types ----------

interface FeeBreakdownProps {
  feeData: FeeCalculation | null | undefined;
  isLoading?: boolean;
}

// ---------- Component ----------

function FeeBreakdown({ feeData, isLoading }: FeeBreakdownProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <DollarSign className="h-4 w-4" />
            Fee Estimate
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Separator />
          <Skeleton className="h-6 w-1/2" />
        </CardContent>
      </Card>
    );
  }

  if (!feeData || !feeData.line_items || feeData.line_items.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <DollarSign className="h-4 w-4" />
            Fee Estimate
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Add HSC code(s) to see fee calculation.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <DollarSign className="h-4 w-4" />
          Fee Estimate
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {feeData.line_items.map((item, index) => (
          <div key={`${item.health_service_code}-${index}`} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="font-mono font-medium">{item.health_service_code}</span>
              <span>{formatCurrency(item.base_fee)}</span>
            </div>

            {item.modifier_adjustments.length > 0 && (
              <div className="ml-4 space-y-0.5">
                {item.modifier_adjustments.map((adj) => (
                  <div
                    key={adj.modifier}
                    className="flex items-center justify-between text-xs text-muted-foreground"
                  >
                    <span className="flex items-center gap-1">
                      <TrendingUp className="h-3 w-3" />
                      Modifier {adj.modifier}
                    </span>
                    <span>
                      {parseFloat(adj.adjustment) >= 0 ? '+' : ''}
                      {formatCurrency(adj.adjustment)}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center justify-between text-sm font-medium">
              <span className="text-muted-foreground">Subtotal</span>
              <span>{formatCurrency(item.calculated_fee)}</span>
            </div>

            {index < feeData.line_items.length - 1 && (
              <Separator className="my-1" />
            )}
          </div>
        ))}

        <Separator />

        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold">Total Fee</span>
          <span className="text-lg font-bold text-primary">
            {formatCurrency(feeData.total_fee)}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

export { FeeBreakdown };
export type { FeeBreakdownProps };
