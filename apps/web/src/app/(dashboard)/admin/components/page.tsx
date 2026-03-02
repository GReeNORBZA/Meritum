'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatRelative } from '@/lib/formatters/date';
import {
  Server,
  Globe,
  Database,
  Link2,
  Shield,
  Cog,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Loader2,
  RefreshCw,
} from 'lucide-react';

// ---------- Types ----------

interface SystemComponent {
  id: string;
  name: string;
  slug: string;
  status: 'operational' | 'degraded' | 'outage';
  description: string;
  last_updated: string;
}

interface ComponentsResponse {
  data: SystemComponent[];
}

type ComponentStatus = SystemComponent['status'];

const STATUS_OPTIONS: { value: ComponentStatus; label: string }[] = [
  { value: 'operational', label: 'Operational' },
  { value: 'degraded', label: 'Degraded Performance' },
  { value: 'outage', label: 'Major Outage' },
];

const COMPONENT_ICONS: Record<string, React.ReactNode> = {
  api: <Server className="h-5 w-5" />,
  'web-app': <Globe className="h-5 w-5" />,
  database: <Database className="h-5 w-5" />,
  'h-link': <Link2 className="h-5 w-5" />,
  'wcb-gateway': <Shield className="h-5 w-5" />,
  'background-jobs': <Cog className="h-5 w-5" />,
};

const statusConfig: Record<
  ComponentStatus,
  { icon: React.ReactNode; variant: 'success' | 'warning' | 'destructive'; label: string }
> = {
  operational: {
    icon: <CheckCircle className="h-4 w-4" />,
    variant: 'success',
    label: 'Operational',
  },
  degraded: {
    icon: <AlertTriangle className="h-4 w-4" />,
    variant: 'warning',
    label: 'Degraded',
  },
  outage: {
    icon: <XCircle className="h-4 w-4" />,
    variant: 'destructive',
    label: 'Outage',
  },
};

// ---------- Main Page ----------

export default function AdminComponentsPage() {
  const queryClient = useQueryClient();

  const queryKey = ['admin', 'components'];

  const { data, isLoading, refetch } = useQuery({
    queryKey,
    queryFn: () => api.get<ComponentsResponse>('/api/v1/admin/components'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: ComponentStatus }) =>
      api.patch(`/api/v1/admin/components/${id}`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
    },
  });

  const components = data?.data ?? [];

  const allOperational = components.every((c) => c.status === 'operational');
  const degradedCount = components.filter((c) => c.status === 'degraded').length;
  const outageCount = components.filter((c) => c.status === 'outage').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Components</h1>
          <p className="text-muted-foreground">
            Monitor and manage the status of system components
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Overall Status */}
      <Card>
        <CardContent className="py-4">
          <div className="flex items-center gap-3">
            {allOperational ? (
              <>
                <CheckCircle className="h-6 w-6 text-green-600" />
                <div>
                  <p className="font-semibold text-green-600">All Systems Operational</p>
                  <p className="text-sm text-muted-foreground">
                    All {components.length} components are functioning normally
                  </p>
                </div>
              </>
            ) : (
              <>
                <AlertTriangle className="h-6 w-6 text-warning" />
                <div>
                  <p className="font-semibold text-warning">System Issues Detected</p>
                  <p className="text-sm text-muted-foreground">
                    {degradedCount > 0 && `${degradedCount} degraded`}
                    {degradedCount > 0 && outageCount > 0 && ', '}
                    {outageCount > 0 && `${outageCount} outage${outageCount !== 1 ? 's' : ''}`}
                  </p>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Component List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="space-y-3">
          {components.map((component) => {
            const config = statusConfig[component.status];
            const icon = COMPONENT_ICONS[component.slug] ?? (
              <Server className="h-5 w-5" />
            );

            return (
              <Card key={component.id}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                        {icon}
                      </div>
                      <div>
                        <p className="font-medium">{component.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {component.description}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="text-right text-sm text-muted-foreground">
                        <p>Last updated</p>
                        <p>{formatRelative(component.last_updated)}</p>
                      </div>

                      <Badge variant={config.variant} className="gap-1">
                        {config.icon}
                        {config.label}
                      </Badge>

                      <Select
                        value={component.status}
                        onValueChange={(val) =>
                          updateMutation.mutate({
                            id: component.id,
                            status: val as ComponentStatus,
                          })
                        }
                        disabled={updateMutation.isPending}
                      >
                        <SelectTrigger className="w-[180px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {STATUS_OPTIONS.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
