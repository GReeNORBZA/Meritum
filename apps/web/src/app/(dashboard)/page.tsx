'use client';

import { DollarSign, FileText, AlertTriangle, Clock } from 'lucide-react';
import { KpiCard } from '@/components/dashboard/kpi-card';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { Skeleton } from '@/components/ui/skeleton';

interface KpiData {
  data: {
    revenue: { current: string; trend: number };
    claimsSubmitted: { current: number; trend: number };
    rejectionRate: { current: number; trend: number };
    pendingClaims: { current: number };
  };
}

export default function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.analytics.kpi(),
    queryFn: () => api.get<KpiData>('/api/v1/analytics/kpis'),
  });

  const kpi = data?.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Welcome back. Here&apos;s your billing overview.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))
        ) : (
          <>
            <KpiCard
              title="Revenue This Month"
              value={kpi?.revenue.current ?? '$0.00'}
              icon={DollarSign}
              trend={kpi?.revenue.trend != null ? { value: kpi.revenue.trend, isPositive: kpi.revenue.trend >= 0 } : undefined}
              description="from last month"
            />
            <KpiCard
              title="Claims Submitted"
              value={kpi?.claimsSubmitted.current ?? 0}
              icon={FileText}
              trend={kpi?.claimsSubmitted.trend != null ? { value: kpi.claimsSubmitted.trend, isPositive: kpi.claimsSubmitted.trend >= 0 } : undefined}
              description="from last month"
            />
            <KpiCard
              title="Rejection Rate"
              value={kpi?.rejectionRate.current != null ? `${kpi.rejectionRate.current}%` : '0%'}
              icon={AlertTriangle}
              trend={kpi?.rejectionRate.trend != null ? { value: kpi.rejectionRate.trend, isPositive: kpi.rejectionRate.trend <= 0 } : undefined}
              description="from last month"
            />
            <KpiCard
              title="Pending Claims"
              value={kpi?.pendingClaims.current ?? 0}
              icon={Clock}
              description="awaiting assessment"
            />
          </>
        )}
      </div>
    </div>
  );
}
