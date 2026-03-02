'use client';

import * as React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Send,
  CheckCircle,
  AlertTriangle,
  Mail,
  Bell,
  Smartphone,
  TrendingUp,
  Loader2,
} from 'lucide-react';

// ---------- Types ----------

interface NotificationStats {
  overview: {
    total_sent: number;
    delivered: number;
    delivery_rate: number;
    email_bounce_rate: number;
    open_rate: number;
    click_rate: number;
  };
  trend: {
    date: string;
    sent: number;
    delivered: number;
    failed: number;
  }[];
  by_channel: {
    channel: string;
    sent: number;
    delivered: number;
    failed: number;
    delivery_rate: number;
  }[];
  by_type: {
    type: string;
    count: number;
    percentage: number;
  }[];
}

interface StatsResponse {
  data: NotificationStats;
}

const PERIOD_OPTIONS = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
] as const;

const CHANNEL_ICONS: Record<string, React.ReactNode> = {
  email: <Mail className="h-4 w-4" />,
  push: <Bell className="h-4 w-4" />,
  sms: <Smartphone className="h-4 w-4" />,
  'in-app': <Bell className="h-4 w-4" />,
};

// ---------- Helper Components ----------

function KpiCard({
  title,
  value,
  subtitle,
  icon,
  trend,
}: {
  title: string;
  value: string;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className="text-muted-foreground">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {subtitle && (
          <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  );
}

function BarChart({
  data,
  maxValue,
  label,
  value,
  barColor = 'bg-primary',
}: {
  data: { label: string; value: number }[];
  maxValue: number;
  label: string;
  value: string;
  barColor?: string;
}) {
  return (
    <div className="space-y-3">
      {data.map((item) => (
        <div key={item.label} className="space-y-1">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{item.label}</span>
            <span className="font-medium">{item.value.toLocaleString()}</span>
          </div>
          <div className="h-2 w-full rounded-full bg-secondary">
            <div
              className={`h-2 rounded-full ${barColor}`}
              style={{
                width: maxValue > 0 ? `${(item.value / maxValue) * 100}%` : '0%',
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------- Main Page ----------

export default function AdminNotificationsPage() {
  const [period, setPeriod] = React.useState('30d');

  const { data, isLoading } = useQuery({
    queryKey: ['admin', 'notifications', 'stats', period],
    queryFn: () =>
      api.get<StatsResponse>('/api/v1/admin/notifications/stats', {
        params: { period },
      }),
  });

  const stats = data?.data;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const overview = stats?.overview ?? {
    total_sent: 0,
    delivered: 0,
    delivery_rate: 0,
    email_bounce_rate: 0,
    open_rate: 0,
    click_rate: 0,
  };

  const trend = stats?.trend ?? [];
  const byChannel = stats?.by_channel ?? [];
  const byType = stats?.by_type ?? [];

  const trendMax = Math.max(...trend.map((t) => t.sent), 1);
  const channelMax = Math.max(...byChannel.map((c) => c.sent), 1);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Notification Stats</h1>
          <p className="text-muted-foreground">
            Monitor notification delivery performance across all channels
          </p>
        </div>
        <Select value={period} onValueChange={setPeriod}>
          <SelectTrigger className="w-[160px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PERIOD_OPTIONS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          title="Total Sent"
          value={overview.total_sent.toLocaleString()}
          subtitle={`${overview.delivered.toLocaleString()} delivered`}
          icon={<Send className="h-4 w-4" />}
        />
        <KpiCard
          title="Delivery Rate"
          value={`${(overview.delivery_rate * 100).toFixed(1)}%`}
          subtitle={`${(overview.total_sent - overview.delivered).toLocaleString()} failed`}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Email Bounce Rate"
          value={`${(overview.email_bounce_rate * 100).toFixed(1)}%`}
          subtitle="Hard + soft bounces"
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <KpiCard
          title="Open Rate"
          value={`${(overview.open_rate * 100).toFixed(1)}%`}
          subtitle={`${(overview.click_rate * 100).toFixed(1)}% click-through`}
          icon={<Mail className="h-4 w-4" />}
        />
      </div>

      <Tabs defaultValue="trend" className="space-y-4">
        <TabsList>
          <TabsTrigger value="trend">
            <TrendingUp className="mr-2 h-4 w-4" />
            Delivery Trend
          </TabsTrigger>
          <TabsTrigger value="channels">
            <Send className="mr-2 h-4 w-4" />
            By Channel
          </TabsTrigger>
          <TabsTrigger value="types">
            <Bell className="mr-2 h-4 w-4" />
            By Type
          </TabsTrigger>
        </TabsList>

        {/* Delivery Trend */}
        <TabsContent value="trend">
          <Card>
            <CardHeader>
              <CardTitle>Delivery Trend</CardTitle>
              <CardDescription>
                Notification volume and delivery status over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              {trend.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">
                  No delivery data available for this period.
                </p>
              ) : (
                <div className="space-y-4">
                  {/* Legend */}
                  <div className="flex gap-4 text-sm">
                    <div className="flex items-center gap-1.5">
                      <div className="h-3 w-3 rounded-full bg-primary" />
                      <span className="text-muted-foreground">Sent</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="h-3 w-3 rounded-full bg-green-500" />
                      <span className="text-muted-foreground">Delivered</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="h-3 w-3 rounded-full bg-destructive" />
                      <span className="text-muted-foreground">Failed</span>
                    </div>
                  </div>

                  {/* Bar chart rows */}
                  <div className="space-y-3">
                    {trend.map((day) => (
                      <div key={day.date} className="space-y-1">
                        <div className="flex items-center justify-between text-xs text-muted-foreground">
                          <span>{day.date}</span>
                          <span>{day.sent.toLocaleString()} sent</span>
                        </div>
                        <div className="flex h-5 w-full overflow-hidden rounded-full bg-secondary">
                          {day.sent > 0 && (
                            <>
                              <div
                                className="h-full bg-green-500"
                                style={{
                                  width: `${(day.delivered / trendMax) * 100}%`,
                                }}
                              />
                              {day.failed > 0 && (
                                <div
                                  className="h-full bg-destructive"
                                  style={{
                                    width: `${(day.failed / trendMax) * 100}%`,
                                  }}
                                />
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* By Channel */}
        <TabsContent value="channels">
          <Card>
            <CardHeader>
              <CardTitle>Breakdown by Channel</CardTitle>
              <CardDescription>
                Delivery performance across notification channels
              </CardDescription>
            </CardHeader>
            <CardContent>
              {byChannel.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">
                  No channel data available.
                </p>
              ) : (
                <div className="space-y-6">
                  {byChannel.map((channel) => (
                    <div key={channel.channel} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {CHANNEL_ICONS[channel.channel] ?? (
                            <Send className="h-4 w-4" />
                          )}
                          <span className="font-medium capitalize">
                            {channel.channel.replace(/-/g, ' ')}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 text-sm">
                          <span>{channel.sent.toLocaleString()} sent</span>
                          <Badge
                            variant={
                              channel.delivery_rate >= 0.95
                                ? 'success'
                                : channel.delivery_rate >= 0.8
                                  ? 'warning'
                                  : 'destructive'
                            }
                          >
                            {(channel.delivery_rate * 100).toFixed(1)}%
                          </Badge>
                        </div>
                      </div>
                      <div className="flex h-3 w-full overflow-hidden rounded-full bg-secondary">
                        <div
                          className="h-full bg-green-500 transition-all"
                          style={{
                            width: channelMax > 0
                              ? `${(channel.delivered / channelMax) * 100}%`
                              : '0%',
                          }}
                        />
                        {channel.failed > 0 && (
                          <div
                            className="h-full bg-destructive transition-all"
                            style={{
                              width: channelMax > 0
                                ? `${(channel.failed / channelMax) * 100}%`
                                : '0%',
                            }}
                          />
                        )}
                      </div>
                      <div className="flex gap-4 text-xs text-muted-foreground">
                        <span>{channel.delivered.toLocaleString()} delivered</span>
                        <span>{channel.failed.toLocaleString()} failed</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* By Type */}
        <TabsContent value="types">
          <Card>
            <CardHeader>
              <CardTitle>Breakdown by Type</CardTitle>
              <CardDescription>
                Notification volume by notification type
              </CardDescription>
            </CardHeader>
            <CardContent>
              {byType.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">
                  No type data available.
                </p>
              ) : (
                <div className="space-y-4">
                  {byType.map((item) => (
                    <div key={item.type} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="capitalize">
                          {item.type.replace(/_/g, ' ')}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">
                            {item.count.toLocaleString()}
                          </span>
                          <Badge variant="outline">
                            {item.percentage.toFixed(1)}%
                          </Badge>
                        </div>
                      </div>
                      <div className="h-2 w-full rounded-full bg-secondary">
                        <div
                          className="h-2 rounded-full bg-primary transition-all"
                          style={{ width: `${item.percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
