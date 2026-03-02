'use client';

import { useState } from 'react';
import { api } from '@/lib/api/client';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Download, Loader2, FileText, Users, BarChart3, Check } from 'lucide-react';

interface ExportType {
  key: string;
  title: string;
  description: string;
  icon: React.ElementType;
}

const EXPORT_TYPES: ExportType[] = [
  { key: 'claims', title: 'Claims', description: 'All AHCIP and WCB claims with history', icon: FileText },
  { key: 'patients', title: 'Patients', description: 'Patient registry and demographics', icon: Users },
  { key: 'analytics', title: 'Analytics', description: 'Revenue and performance data', icon: BarChart3 },
];

export default function ExportPage() {
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [completed, setCompleted] = useState<Record<string, string>>({});

  const handleExport = async (type: string) => {
    setLoading((prev) => ({ ...prev, [type]: true }));
    try {
      const res = await api.post<{ data: { download_url: string } }>('/api/v1/platform/export/full', { type });
      setCompleted((prev) => ({ ...prev, [type]: res.data.download_url }));
    } catch {
      // Error handled by API client toast
    } finally {
      setLoading((prev) => ({ ...prev, [type]: false }));
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Data Export</h1>
        <p className="text-muted-foreground">Download your data for portability or record-keeping</p>
      </div>

      <div className="grid gap-4">
        {EXPORT_TYPES.map(({ key, title, description, icon: Icon }) => (
          <Card key={key}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Icon className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <CardTitle className="text-base">{title}</CardTitle>
                    <CardDescription>{description}</CardDescription>
                  </div>
                </div>
                {completed[key] ? (
                  <a href={completed[key]} download>
                    <Button variant="outline" size="sm">
                      <Check className="mr-2 h-4 w-4 text-success" />
                      Download
                    </Button>
                  </a>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleExport(key)}
                    disabled={loading[key]}
                  >
                    {loading[key] ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Download className="mr-2 h-4 w-4" />
                    )}
                    Generate
                  </Button>
                )}
              </div>
            </CardHeader>
          </Card>
        ))}
      </div>
    </div>
  );
}
