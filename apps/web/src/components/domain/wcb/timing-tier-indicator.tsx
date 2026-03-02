'use client';

import * as React from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Clock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

interface TimingTierIndicatorProps {
  timingTier?: string;
  deadlineInfo?: {
    same_day_deadline?: string;
    on_time_deadline?: string;
    is_past_deadline: boolean;
    business_days_remaining?: number;
  };
  className?: string;
}

const TIER_CONFIG: Record<string, {
  label: string;
  description: string;
  variant: 'success' | 'warning' | 'destructive';
  icon: React.ElementType;
}> = {
  SAME_DAY: {
    label: 'Same Day',
    description: 'Highest fee tier - submitted on exam day or next business day',
    variant: 'success',
    icon: CheckCircle,
  },
  ON_TIME: {
    label: 'On Time',
    description: 'Standard fee tier - submitted within deadline',
    variant: 'warning',
    icon: Clock,
  },
  LATE: {
    label: 'Late',
    description: 'Reduced fee tier - submitted after deadline',
    variant: 'destructive',
    icon: XCircle,
  },
};

function TimingTierIndicator({ timingTier, deadlineInfo, className }: TimingTierIndicatorProps) {
  const tierConfig = timingTier ? TIER_CONFIG[timingTier] : null;

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Clock className="h-4 w-4" />
          Timing Tier
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {tierConfig ? (
          <>
            <div className="flex items-center gap-2">
              <tierConfig.icon className="h-5 w-5" />
              <Badge variant={tierConfig.variant} className="text-sm">
                {tierConfig.label}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">{tierConfig.description}</p>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">
            Timing tier will be calculated after the examination date is set.
          </p>
        )}

        {deadlineInfo && (
          <div className="space-y-2 border-t pt-3">
            {deadlineInfo.business_days_remaining != null && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Days Remaining</span>
                <span className="font-medium">
                  {deadlineInfo.business_days_remaining} business day
                  {deadlineInfo.business_days_remaining !== 1 ? 's' : ''}
                </span>
              </div>
            )}
            {deadlineInfo.is_past_deadline && (
              <div className="flex items-start gap-2 rounded-md bg-destructive/10 p-2 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  This claim is past the on-time deadline. A reduced late fee will apply.
                </span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export { TimingTierIndicator };
export type { TimingTierIndicatorProps };
