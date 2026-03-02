'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusBadge } from '@/components/shared/status-badge';
import { CreditCard, ExternalLink } from 'lucide-react';
import { formatDate } from '@/lib/formatters/date';
import { formatCurrency } from '@/lib/formatters/currency';

interface Subscription {
  status: string;
  plan_name: string;
  amount: number;
  currency: string;
  interval: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  payment_method?: {
    brand: string;
    last4: string;
    exp_month: number;
    exp_year: number;
  };
}

export default function SubscriptionPage() {
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.subscription.status(),
    queryFn: () => api.get<{ data: Subscription }>('/api/v1/subscriptions/current'),
  });

  const sub = data?.data;

  const handleManage = async () => {
    const res = await api.post<{ data: { url: string } }>('/api/v1/subscriptions/portal', {});
    window.open(res.data.url, '_blank');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Subscription</h1>
        <p className="text-muted-foreground">Manage your billing and subscription</p>
      </div>

      {isLoading ? (
        <Skeleton className="h-48" />
      ) : sub ? (
        <>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{sub.plan_name}</CardTitle>
                  <CardDescription>
                    {formatCurrency(sub.amount / 100)} / {sub.interval}
                  </CardDescription>
                </div>
                <StatusBadge status={sub.status} />
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <p className="text-sm text-muted-foreground">Next billing date</p>
                  <p className="text-sm font-medium">{formatDate(sub.current_period_end)}</p>
                </div>
                {sub.cancel_at_period_end && (
                  <div>
                    <p className="text-sm text-destructive font-medium">Cancels at period end</p>
                  </div>
                )}
              </div>
              {sub.payment_method && (
                <div className="flex items-center gap-3 rounded-md border p-3">
                  <CreditCard className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="text-sm font-medium capitalize">{sub.payment_method.brand} ending in {sub.payment_method.last4}</p>
                    <p className="text-xs text-muted-foreground">Expires {sub.payment_method.exp_month}/{sub.payment_method.exp_year}</p>
                  </div>
                </div>
              )}
              <Button onClick={handleManage}>
                Manage Subscription
                <ExternalLink className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        </>
      ) : (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-muted-foreground">No active subscription found.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
