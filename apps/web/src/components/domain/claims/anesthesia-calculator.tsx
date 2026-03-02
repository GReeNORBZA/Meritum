'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { formatCurrency } from '@/lib/formatters/currency';
import { Calculator, Clock, Hash, Layers } from 'lucide-react';

/**
 * Alberta anesthesia billing constants.
 * The per-unit rate is used to convert total units to a dollar fee.
 * Time units are calculated as 1 unit per 15 minutes.
 */
const ANESTHESIA_UNIT_RATE_CENTS = 1530; // $15.30 per unit
const MINUTES_PER_TIME_UNIT = 15;

/** Well-known modifier adjustments expressed as percentage multipliers. */
const MODIFIER_ADJUSTMENTS: Record<string, { label: string; multiplier: number }> = {
  ANA: { label: 'Age (Newborn)', multiplier: 1.0 },
  E: { label: 'Emergency', multiplier: 0.5 },
  L: { label: 'Late evening/Night', multiplier: 0.5 },
  BMI: { label: 'BMI > 40', multiplier: 0.25 },
};

interface AnesthesiaCalculatorProps {
  baseUnits: number;
  timeMinutes: number;
  modifiers?: string[];
  unitRate?: number;
  className?: string;
}

interface CalculationBreakdown {
  baseUnits: number;
  timeUnits: number;
  totalUnits: number;
  modifierUnits: number;
  grandTotalUnits: number;
  feeCents: number;
  modifierDetails: Array<{ code: string; label: string; additionalUnits: number }>;
}

function calculateAnesthesia(
  baseUnits: number,
  timeMinutes: number,
  modifiers: string[],
  unitRateCents: number
): CalculationBreakdown {
  const timeUnits = Math.ceil(timeMinutes / MINUTES_PER_TIME_UNIT);
  const totalUnits = baseUnits + timeUnits;

  let modifierUnits = 0;
  const modifierDetails: CalculationBreakdown['modifierDetails'] = [];

  for (const code of modifiers) {
    const adj = MODIFIER_ADJUSTMENTS[code];
    if (adj) {
      const additional = Math.round(totalUnits * adj.multiplier * 100) / 100;
      modifierUnits += additional;
      modifierDetails.push({
        code,
        label: adj.label,
        additionalUnits: additional,
      });
    }
  }

  const grandTotalUnits = totalUnits + modifierUnits;
  const feeCents = Math.round(grandTotalUnits * unitRateCents);

  return {
    baseUnits,
    timeUnits,
    totalUnits,
    modifierUnits,
    grandTotalUnits,
    feeCents,
    modifierDetails,
  };
}

export function AnesthesiaCalculator({
  baseUnits,
  timeMinutes,
  modifiers = [],
  unitRate = ANESTHESIA_UNIT_RATE_CENTS,
  className,
}: AnesthesiaCalculatorProps) {
  const breakdown = useMemo(
    () => calculateAnesthesia(baseUnits, timeMinutes, modifiers, unitRate),
    [baseUnits, timeMinutes, modifiers, unitRate]
  );

  const formattedFee = formatCurrency(breakdown.feeCents / 100);

  return (
    <Card className={cn('', className)}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Calculator className="h-4 w-4" />
          Anesthesia Calculator
        </CardTitle>
        <CardDescription>
          Base units + time units + modifier adjustments
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Breakdown rows */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 text-muted-foreground">
              <Hash className="h-3.5 w-3.5" />
              Base Units
            </span>
            <span className="font-mono font-medium">{breakdown.baseUnits}</span>
          </div>

          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              Time Units
              <span className="text-xs">
                ({timeMinutes} min / {MINUTES_PER_TIME_UNIT} min)
              </span>
            </span>
            <span className="font-mono font-medium">{breakdown.timeUnits}</span>
          </div>

          <div className="border-t pt-2 flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Subtotal Units</span>
            <span className="font-mono font-medium">
              {breakdown.totalUnits}
            </span>
          </div>

          {/* Modifier adjustments */}
          {breakdown.modifierDetails.length > 0 && (
            <>
              <div className="border-t pt-2">
                <span className="flex items-center gap-2 text-sm text-muted-foreground mb-1.5">
                  <Layers className="h-3.5 w-3.5" />
                  Modifier Adjustments
                </span>
                <div className="space-y-1 pl-5">
                  {breakdown.modifierDetails.map((mod) => (
                    <div
                      key={mod.code}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="text-muted-foreground">
                        <Badge
                          variant="outline"
                          className="font-mono text-xs mr-1.5"
                        >
                          {mod.code}
                        </Badge>
                        {mod.label}
                      </span>
                      <span className="font-mono text-sm">
                        +{mod.additionalUnits}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Total */}
        <div className="rounded-md bg-muted p-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Total Units</p>
              <p className="text-xs text-muted-foreground">
                @ {formatCurrency(unitRate / 100)} per unit
              </p>
            </div>
            <div className="text-right">
              <p className="font-mono text-sm">
                {breakdown.grandTotalUnits} units
              </p>
              <p className="text-lg font-bold">{formattedFee}</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
