'use client';

import { AlertTriangle, X } from 'lucide-react';
import { useState } from 'react';
import Link from 'next/link';
import { useAuthStore } from '@/stores/auth.store';
import { ROUTES } from '@/config/routes';
import { Button } from '@/components/ui/button';

export function SubscriptionBanner() {
  const { user } = useAuthStore();
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  const status = user?.subscriptionStatus;

  if (!status || status === 'active' || status === 'trialing') return null;

  const messages: Record<string, { text: string; variant: 'warning' | 'destructive' }> = {
    past_due: {
      text: 'Your payment is past due. Please update your payment method to avoid service interruption.',
      variant: 'warning',
    },
    suspended: {
      text: 'Your account has been suspended due to unpaid invoices. Please update your payment method.',
      variant: 'destructive',
    },
    cancelled: {
      text: 'Your subscription has been cancelled. Resubscribe to regain full access.',
      variant: 'destructive',
    },
    incomplete: {
      text: 'Your subscription setup is incomplete. Please complete your payment.',
      variant: 'warning',
    },
  };

  const msg = messages[status];
  if (!msg) return null;

  return (
    <div
      className={`flex items-center gap-3 px-4 py-2 text-sm ${
        msg.variant === 'destructive'
          ? 'bg-destructive/10 text-destructive'
          : 'bg-warning/10 text-warning'
      }`}
    >
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <p className="flex-1">{msg.text}</p>
      <Link href={ROUTES.SETTINGS_SUBSCRIPTION}>
        <Button variant="outline" size="sm">
          Manage Subscription
        </Button>
      </Link>
      <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setDismissed(true)}>
        <X className="h-3 w-3" />
      </Button>
    </div>
  );
}
