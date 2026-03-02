'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';

interface SystemComponent {
  name: string;
  status: 'operational' | 'degraded' | 'outage';
}

interface StatusData {
  overall: 'operational' | 'degraded' | 'outage';
  components: SystemComponent[];
  incidents: { id: string; title: string; status: string; created_at: string }[];
}

const statusIcons = {
  operational: CheckCircle2,
  degraded: AlertTriangle,
  outage: XCircle,
};

const statusColors = {
  operational: 'text-success',
  degraded: 'text-warning',
  outage: 'text-destructive',
};

export default function StatusPage() {
  const { data } = useQuery({
    queryKey: ['status'],
    queryFn: () => api.get<{ data: StatusData }>('/api/v1/status'),
    refetchInterval: 60000,
  });

  const status = data?.data;
  const OverallIcon = status ? statusIcons[status.overall] : CheckCircle2;

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto max-w-2xl px-4 py-12">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold mb-2">Meritum System Status</h1>
          {status && (
            <div className={`inline-flex items-center gap-2 ${statusColors[status.overall]}`}>
              <OverallIcon className="h-5 w-5" />
              <span className="font-medium capitalize">
                {status.overall === 'operational' ? 'All Systems Operational' : status.overall}
              </span>
            </div>
          )}
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Components</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {status?.components.map((component) => {
                const Icon = statusIcons[component.status];
                return (
                  <div key={component.name} className="flex items-center justify-between">
                    <span className="text-sm">{component.name}</span>
                    <div className={`flex items-center gap-1.5 ${statusColors[component.status]}`}>
                      <Icon className="h-4 w-4" />
                      <span className="text-xs capitalize">{component.status}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {status?.incidents && status.incidents.length > 0 && (
          <Card className="mt-4">
            <CardHeader>
              <CardTitle>Recent Incidents</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {status.incidents.map((incident) => (
                  <div key={incident.id} className="border-l-2 border-warning pl-3">
                    <p className="text-sm font-medium">{incident.title}</p>
                    <p className="text-xs text-muted-foreground">{incident.status}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
