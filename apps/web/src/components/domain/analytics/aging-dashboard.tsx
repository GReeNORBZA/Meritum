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
import { Badge } from '@/components/ui/badge';
import { useAgingAnalytics, type AnalyticsPeriod } from '@/hooks/api/use-analytics';
import { formatCurrency } from '@/lib/formatters/currency';
import { Clock, AlertTriangle } from 'lucide-react';

interface AgingDashboardProps {
  period: AnalyticsPeriod;
  dateFrom?: string;
  dateTo?: string;
}

export function AgingDashboard({ period, dateFrom, dateTo }: AgingDashboardProps) {
  const { data, isLoading } = useAgingAnalytics(period, dateFrom, dateTo);
  const analytics = data?.data;

  if (isLoading) {
    return <AgingDashboardSkeleton />;
  }

  if (!analytics) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        No aging data available for the selected period.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Total Outstanding */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Outstanding</CardTitle>
          <Clock className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatCurrency(analytics.total_outstanding)}</div>
          <p className="text-xs text-muted-foreground">
            Total value of outstanding claims
          </p>
        </CardContent>
      </Card>

      {/* Stacked Bar Chart: Claims by Age Bracket */}
      <Card>
        <CardHeader>
          <CardTitle>Claims by Age Bracket</CardTitle>
          <CardDescription>
            Distribution of outstanding claims by days since submission
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[350px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics.brackets}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="bracket"
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                />
                <YAxis
                  yAxisId="left"
                  className="text-xs"
                  tick={{ fill: 'hsl(var(--muted-foreground))' }}
                />
                <YAxis
                  yAxisId="right"
                  orientation="right"
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
                  formatter={(value: number, name: string) => {
                    if (name === 'Amount') return [formatCurrency(value), 'Amount'];
                    return [value, 'Claims'];
                  }}
                />
                <Legend />
                <Bar
                  yAxisId="left"
                  dataKey="count"
                  name="Claims"
                  fill="hsl(var(--chart-1))"
                  radius={[4, 4, 0, 0]}
                />
                <Bar
                  yAxisId="right"
                  dataKey="amount"
                  name="Amount"
                  fill="hsl(var(--chart-2))"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Claims Approaching Deadline Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            Claims Approaching Deadline
          </CardTitle>
          <CardDescription>
            Claims that are nearing the submission or reassessment deadline
          </CardDescription>
        </CardHeader>
        <CardContent>
          {analytics.approaching_deadline.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              No claims approaching deadline.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="pb-3 text-left font-medium text-muted-foreground">Claim #</th>
                    <th className="pb-3 text-left font-medium text-muted-foreground">Patient</th>
                    <th className="pb-3 text-left font-medium text-muted-foreground">Service Date</th>
                    <th className="pb-3 text-right font-medium text-muted-foreground">Age (days)</th>
                    <th className="pb-3 text-right font-medium text-muted-foreground">Amount</th>
                    <th className="pb-3 text-left font-medium text-muted-foreground">Deadline</th>
                    <th className="pb-3 text-left font-medium text-muted-foreground">Urgency</th>
                  </tr>
                </thead>
                <tbody>
                  {analytics.approaching_deadline.map((claim) => {
                    const daysUntilDeadline = Math.max(
                      0,
                      Math.ceil(
                        (new Date(claim.deadline_date).getTime() - Date.now()) /
                          (1000 * 60 * 60 * 24)
                      )
                    );
                    const urgency =
                      daysUntilDeadline <= 7
                        ? 'critical'
                        : daysUntilDeadline <= 14
                          ? 'warning'
                          : 'normal';

                    return (
                      <tr key={claim.id} className="border-b last:border-0">
                        <td className="py-3 font-mono text-sm">{claim.claim_number}</td>
                        <td className="py-3">{claim.patient_name}</td>
                        <td className="py-3">{claim.date_of_service}</td>
                        <td className="py-3 text-right">{claim.age_days}</td>
                        <td className="py-3 text-right font-medium">
                          {formatCurrency(claim.amount)}
                        </td>
                        <td className="py-3">{claim.deadline_date}</td>
                        <td className="py-3">
                          <Badge
                            variant={
                              urgency === 'critical'
                                ? 'destructive'
                                : urgency === 'warning'
                                  ? 'secondary'
                                  : 'outline'
                            }
                          >
                            {daysUntilDeadline} days left
                          </Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function AgingDashboardSkeleton() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 w-4" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-8 w-32 mb-2" />
          <Skeleton className="h-3 w-48" />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[350px] w-full" />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-48" />
          <Skeleton className="h-4 w-72" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
