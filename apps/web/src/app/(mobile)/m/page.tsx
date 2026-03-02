'use client';

import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { ROUTES } from '@/config/routes';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  DollarSign,
  FileText,
  Clock,
  AlertTriangle,
  Plus,
  PlayCircle,
  Users,
  Loader2,
} from 'lucide-react';
import type { ApiResponse } from '@/lib/api/client';

interface KpiData {
  revenue: { amount: string; change_pct: number };
  claims_today: { count: number; change_pct: number };
  pending: { count: number };
  rejection_rate: { rate: number; change_pct: number };
}

export default function MobileHomePage() {
  const router = useRouter();

  const { data, isLoading, error } = useQuery({
    queryKey: queryKeys.analytics.kpi(),
    queryFn: () => api.get<ApiResponse<KpiData>>('/api/v1/analytics/kpis'),
  });

  const kpi = data?.data;

  const kpiCards = [
    {
      label: 'Revenue',
      value: kpi ? `$${Number(kpi.revenue.amount).toLocaleString()}` : '--',
      change: kpi?.revenue.change_pct,
      icon: DollarSign,
      color: 'text-green-600',
    },
    {
      label: 'Claims Today',
      value: kpi?.claims_today.count ?? '--',
      change: kpi?.claims_today.change_pct,
      icon: FileText,
      color: 'text-blue-600',
    },
    {
      label: 'Pending',
      value: kpi?.pending.count ?? '--',
      change: undefined,
      icon: Clock,
      color: 'text-amber-600',
    },
    {
      label: 'Rejection Rate',
      value: kpi ? `${kpi.rejection_rate.rate}%` : '--',
      change: kpi?.rejection_rate.change_pct,
      icon: AlertTriangle,
      color: 'text-red-600',
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold">Dashboard</h1>

      {/* KPI Cards */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : error ? (
        <Card>
          <CardContent className="py-6 text-center text-sm text-destructive">
            Failed to load dashboard data. Pull down to retry.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-2 gap-3">
          {kpiCards.map(({ label, value, change, icon: Icon, color }) => (
            <Card key={label}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground">
                  {label}
                </CardTitle>
                <Icon className={`h-4 w-4 ${color}`} />
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="text-lg font-bold">{value}</div>
                {change !== undefined && (
                  <p className="text-xs text-muted-foreground">
                    <span className={change >= 0 ? 'text-green-600' : 'text-red-600'}>
                      {change >= 0 ? '+' : ''}
                      {change}%
                    </span>{' '}
                    vs last period
                  </p>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Quick Actions */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
          Quick Actions
        </h2>
        <div className="grid grid-cols-3 gap-2">
          <Button
            variant="outline"
            className="flex flex-col items-center gap-1.5 h-auto py-4"
            onClick={() => router.push(ROUTES.MOBILE_CLAIM)}
          >
            <Plus className="h-5 w-5" />
            <span className="text-xs">New Claim</span>
          </Button>
          <Button
            variant="outline"
            className="flex flex-col items-center gap-1.5 h-auto py-4"
            onClick={() => router.push(ROUTES.MOBILE_SHIFT)}
          >
            <PlayCircle className="h-5 w-5" />
            <span className="text-xs">Start Shift</span>
          </Button>
          <Button
            variant="outline"
            className="flex flex-col items-center gap-1.5 h-auto py-4"
            onClick={() => router.push(ROUTES.PATIENTS)}
          >
            <Users className="h-5 w-5" />
            <span className="text-xs">Patients</span>
          </Button>
        </div>
      </div>
    </div>
  );
}
