'use client';

import * as React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useMultiSiteAnalytics, type AnalyticsPeriod } from '@/hooks/api/use-analytics';
import { formatCurrency } from '@/lib/formatters/currency';
import { Building2, DollarSign, FileText } from 'lucide-react';

interface MultiSiteDashboardProps {
  period: AnalyticsPeriod;
  dateFrom?: string;
  dateTo?: string;
}

export function MultiSiteDashboard({ period, dateFrom, dateTo }: MultiSiteDashboardProps) {
  const { data, isLoading } = useMultiSiteAnalytics(period, dateFrom, dateTo);
  const analytics = data?.data;

  if (isLoading) {
    return <MultiSiteDashboardSkeleton />;
  }

  if (!analytics) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        No multi-site data available for the selected period.
      </div>
    );
  }

  // Prepare chart data sorted by revenue descending
  const revenueData = [...analytics.sites].sort((a, b) => b.revenue - a.revenue);
  const volumeData = [...analytics.sites].sort((a, b) => b.claims_count - a.claims_count);
  const rejectionData = [...analytics.sites].sort((a, b) => b.rejection_rate - a.rejection_rate);

  return (
    <div className="space-y-6">
      {/* Summary KPI Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Locations</CardTitle>
            <Building2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.sites.length}</div>
            <p className="text-xs text-muted-foreground">Active practice locations</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Combined Revenue</CardTitle>
            <DollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatCurrency(analytics.total_revenue)}</div>
            <p className="text-xs text-muted-foreground">Across all locations</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Claims</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.total_claims.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">Combined claims volume</p>
          </CardContent>
        </Card>
      </div>

      {/* Revenue by Location */}
      <Card>
        <CardHeader>
          <CardTitle>Revenue by Location</CardTitle>
          <CardDescription>Revenue comparison across practice locations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={revenueData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="location_name"
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                  angle={-30}
                  textAnchor="end"
                  height={80}
                />
                <YAxis
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                  tickFormatter={(value) => `$${(value / 1000).toFixed(0)}k`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--popover))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                    color: 'hsl(var(--popover-foreground))',
                  }}
                  formatter={(value: number) => [formatCurrency(value), 'Revenue']}
                />
                <Bar
                  dataKey="revenue"
                  name="Revenue"
                  fill="hsl(var(--chart-1))"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Claims Volume by Location */}
      <Card>
        <CardHeader>
          <CardTitle>Claims Volume by Location</CardTitle>
          <CardDescription>Number of claims processed at each location</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={volumeData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="location_name"
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                  angle={-30}
                  textAnchor="end"
                  height={80}
                />
                <YAxis
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--popover))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                    color: 'hsl(var(--popover-foreground))',
                  }}
                  formatter={(value: number) => [value.toLocaleString(), 'Claims']}
                />
                <Bar
                  dataKey="claims_count"
                  name="Claims"
                  fill="hsl(var(--chart-2))"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Rejection Rate by Location */}
      <Card>
        <CardHeader>
          <CardTitle>Rejection Rate by Location</CardTitle>
          <CardDescription>
            Claim rejection rates compared across locations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={rejectionData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="location_name"
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                  angle={-30}
                  textAnchor="end"
                  height={80}
                />
                <YAxis
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                  tickFormatter={(value) => `${value}%`}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--popover))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                    color: 'hsl(var(--popover-foreground))',
                  }}
                  formatter={(value: number) => [`${value.toFixed(1)}%`, 'Rejection Rate']}
                />
                <Bar
                  dataKey="rejection_rate"
                  name="Rejection Rate"
                  fill="hsl(var(--chart-3))"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function MultiSiteDashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-20 mb-2" />
              <Skeleton className="h-3 w-40" />
            </CardContent>
          </Card>
        ))}
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i}>
          <CardHeader>
            <Skeleton className="h-5 w-44" />
            <Skeleton className="h-4 w-60" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[400px] w-full" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
