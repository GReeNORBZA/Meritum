'use client';

import * as React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { RevenueDashboard } from '@/components/domain/analytics/revenue-dashboard';
import { RejectionDashboard } from '@/components/domain/analytics/rejection-dashboard';
import { AgingDashboard } from '@/components/domain/analytics/aging-dashboard';
import { WcbDashboard } from '@/components/domain/analytics/wcb-dashboard';
import { AiCoachDashboard } from '@/components/domain/analytics/ai-coach-dashboard';
import { MultiSiteDashboard } from '@/components/domain/analytics/multi-site-dashboard';
import type { AnalyticsPeriod } from '@/hooks/api/use-analytics';
import {
  DollarSign,
  XCircle,
  Clock,
  HardHat,
  Brain,
  Building2,
} from 'lucide-react';

const PERIOD_OPTIONS = [
  { value: 'this_week', label: 'This Week' },
  { value: 'this_month', label: 'This Month' },
  { value: 'this_quarter', label: 'This Quarter' },
  { value: 'this_year', label: 'This Year' },
  { value: 'custom', label: 'Custom Range' },
] as const;

export default function AnalyticsPage() {
  const [period, setPeriod] = React.useState<AnalyticsPeriod>('this_month');
  const [activeTab, setActiveTab] = React.useState('revenue');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
          <p className="text-muted-foreground">
            Insights and performance metrics for your billing practice
          </p>
        </div>

        <Select
          value={period}
          onValueChange={(val) => setPeriod(val as AnalyticsPeriod)}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Select period..." />
          </SelectTrigger>
          <SelectContent>
            {PERIOD_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex w-full flex-wrap gap-1">
          <TabsTrigger value="revenue" className="flex items-center gap-1.5">
            <DollarSign className="h-3.5 w-3.5" />
            Revenue
          </TabsTrigger>
          <TabsTrigger value="rejections" className="flex items-center gap-1.5">
            <XCircle className="h-3.5 w-3.5" />
            Rejections
          </TabsTrigger>
          <TabsTrigger value="aging" className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            Aging
          </TabsTrigger>
          <TabsTrigger value="wcb" className="flex items-center gap-1.5">
            <HardHat className="h-3.5 w-3.5" />
            WCB
          </TabsTrigger>
          <TabsTrigger value="ai-coach" className="flex items-center gap-1.5">
            <Brain className="h-3.5 w-3.5" />
            AI Coach
          </TabsTrigger>
          <TabsTrigger value="multi-site" className="flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5" />
            Multi-Site
          </TabsTrigger>
        </TabsList>

        <TabsContent value="revenue">
          <RevenueDashboard period={period} />
        </TabsContent>

        <TabsContent value="rejections">
          <RejectionDashboard period={period} />
        </TabsContent>

        <TabsContent value="aging">
          <AgingDashboard period={period} />
        </TabsContent>

        <TabsContent value="wcb">
          <WcbDashboard period={period} />
        </TabsContent>

        <TabsContent value="ai-coach">
          <AiCoachDashboard period={period} />
        </TabsContent>

        <TabsContent value="multi-site">
          <MultiSiteDashboard period={period} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
