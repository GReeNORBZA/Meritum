'use client';

import { Badge, type BadgeProps } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

const statusVariantMap: Record<string, BadgeProps['variant']> = {
  // Claim states
  DRAFT: 'secondary',
  VALIDATED: 'default',
  QUEUED: 'default',
  SUBMITTED: 'default',
  ACCEPTED: 'success',
  PAID: 'success',
  REJECTED: 'destructive',
  WRITTEN_OFF: 'outline',
  // Subscription
  active: 'success',
  trialing: 'success',
  past_due: 'warning',
  suspended: 'destructive',
  cancelled: 'destructive',
  // Generic
  ACTIVE: 'success',
  INACTIVE: 'secondary',
  PENDING: 'warning',
  COMPLETED: 'success',
  FAILED: 'destructive',
  OPEN: 'warning',
  CLOSED: 'secondary',
  RESOLVED: 'success',
};

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const variant = statusVariantMap[status] || 'outline';
  const label = status.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());

  return (
    <Badge variant={variant} className={cn('font-medium', className)}>
      {label}
    </Badge>
  );
}
