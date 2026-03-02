'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatDateTime, formatRelative } from '@/lib/formatters/date';
import { Plus, Pencil, AlertTriangle, Loader2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface Incident {
  id: string;
  title: string;
  status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
  severity: 'minor' | 'major' | 'critical';
  message: string;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  updates: IncidentUpdate[];
}

interface IncidentUpdate {
  id: string;
  status: Incident['status'];
  message: string;
  created_at: string;
}

interface IncidentsResponse {
  data: Incident[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

interface IncidentFormData {
  title: string;
  status: Incident['status'];
  severity: Incident['severity'];
  message: string;
}

const INCIDENT_STATUSES = [
  { value: 'investigating', label: 'Investigating' },
  { value: 'identified', label: 'Identified' },
  { value: 'monitoring', label: 'Monitoring' },
  { value: 'resolved', label: 'Resolved' },
] as const;

const SEVERITY_OPTIONS = [
  { value: 'minor', label: 'Minor' },
  { value: 'major', label: 'Major' },
  { value: 'critical', label: 'Critical' },
] as const;

const EMPTY_FORM: IncidentFormData = {
  title: '',
  status: 'investigating',
  severity: 'minor',
  message: '',
};

const severityVariantMap: Record<string, 'secondary' | 'warning' | 'destructive'> = {
  minor: 'secondary',
  major: 'warning',
  critical: 'destructive',
};

// ---------- Main Page ----------

export default function AdminIncidentsPage() {
  const queryClient = useQueryClient();

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editingIncident, setEditingIncident] = React.useState<Incident | null>(null);
  const [formData, setFormData] = React.useState<IncidentFormData>(EMPTY_FORM);

  const queryKey = ['admin', 'incidents', { page, pageSize }];

  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      api.get<IncidentsResponse>('/api/v1/admin/incidents', {
        params: { page, pageSize },
      }),
  });

  const createMutation = useMutation({
    mutationFn: (payload: IncidentFormData) =>
      api.post('/api/v1/admin/incidents', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'incidents'] });
      closeDialog();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...payload }: IncidentFormData & { id: string }) =>
      api.put(`/api/v1/admin/incidents/${id}`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'incidents'] });
      closeDialog();
    },
  });

  const openCreate = () => {
    setEditingIncident(null);
    setFormData(EMPTY_FORM);
    setDialogOpen(true);
  };

  const openEdit = (incident: Incident) => {
    setEditingIncident(incident);
    setFormData({
      title: incident.title,
      status: incident.status,
      severity: incident.severity,
      message: '',
    });
    setDialogOpen(true);
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setEditingIncident(null);
    setFormData(EMPTY_FORM);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingIncident) {
      updateMutation.mutate({ id: editingIncident.id, ...formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const isSaving = createMutation.isPending || updateMutation.isPending;

  // ---------- Columns ----------

  const columns: ColumnDef<Incident>[] = [
    {
      accessorKey: 'title',
      header: 'Title',
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          {row.original.severity === 'critical' && (
            <AlertTriangle className="h-4 w-4 text-destructive" />
          )}
          <span className="text-sm font-medium">{row.original.title}</span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const status = row.original.status;
        const statusMap: Record<string, string> = {
          investigating: 'PENDING',
          identified: 'OPEN',
          monitoring: 'ACTIVE',
          resolved: 'RESOLVED',
        };
        return <StatusBadge status={statusMap[status] ?? status.toUpperCase()} />;
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: ({ row }) => (
        <Badge
          variant={severityVariantMap[row.original.severity] ?? 'outline'}
          className="capitalize"
        >
          {row.original.severity}
        </Badge>
      ),
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatDateTime(row.original.created_at)}
        </span>
      ),
    },
    {
      accessorKey: 'updated_at',
      header: 'Updated',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelative(row.original.updated_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => openEdit(row.original)}
          >
            <Pencil className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  // ---------- Summary ----------

  const incidents = data?.data ?? [];
  const activeIncidents = incidents.filter((i) => i.status !== 'resolved');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Incidents</h1>
          <p className="text-muted-foreground">
            Manage status page incidents and communicate with users
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          New Incident
        </Button>
      </div>

      {/* Active Incidents Banner */}
      {activeIncidents.length > 0 && (
        <div className="rounded-lg border border-warning bg-warning/10 p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-5 w-5 text-warning" />
            <span className="font-semibold">
              {activeIncidents.length} Active Incident{activeIncidents.length !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="space-y-1">
            {activeIncidents.map((incident) => (
              <div key={incident.id} className="flex items-center justify-between text-sm">
                <span>{incident.title}</span>
                <Badge
                  variant={severityVariantMap[incident.severity] ?? 'outline'}
                  className="capitalize"
                >
                  {incident.status}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={incidents}
        isLoading={isLoading}
        pagination={{
          page,
          pageSize,
          total: data?.pagination?.total ?? 0,
        }}
        onPaginationChange={(newPage, newPageSize) => {
          setPage(newPage);
          setPageSize(newPageSize);
        }}
      />

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingIncident ? 'Update Incident' : 'Create Incident'}
            </DialogTitle>
            <DialogDescription>
              {editingIncident
                ? 'Post an update to this incident. Status changes will be reflected on the public status page.'
                : 'Create a new incident to communicate system issues.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="incident-title">Title</Label>
              <Input
                id="incident-title"
                value={formData.title}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, title: e.target.value }))
                }
                placeholder="e.g. Elevated API Error Rates"
                required
                disabled={!!editingIncident}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="incident-status">Status</Label>
                <Select
                  value={formData.status}
                  onValueChange={(val) =>
                    setFormData((prev) => ({
                      ...prev,
                      status: val as Incident['status'],
                    }))
                  }
                >
                  <SelectTrigger id="incident-status">
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    {INCIDENT_STATUSES.map((s) => (
                      <SelectItem key={s.value} value={s.value}>
                        {s.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="incident-severity">Severity</Label>
                <Select
                  value={formData.severity}
                  onValueChange={(val) =>
                    setFormData((prev) => ({
                      ...prev,
                      severity: val as Incident['severity'],
                    }))
                  }
                >
                  <SelectTrigger id="incident-severity">
                    <SelectValue placeholder="Select severity" />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((s) => (
                      <SelectItem key={s.value} value={s.value}>
                        {s.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="incident-message">
                {editingIncident ? 'Update Message' : 'Message'}
              </Label>
              <Textarea
                id="incident-message"
                value={formData.message}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, message: e.target.value }))
                }
                placeholder="Describe the issue or provide an update..."
                rows={4}
                required
              />
            </div>

            {/* Previous updates timeline (edit mode) */}
            {editingIncident && editingIncident.updates.length > 0 && (
              <div className="space-y-2">
                <Label>Previous Updates</Label>
                <div className="max-h-40 overflow-y-auto space-y-2 rounded-md border p-3">
                  {editingIncident.updates.map((update) => (
                    <div key={update.id} className="border-l-2 border-muted pl-3 text-sm">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className="text-xs capitalize">
                          {update.status}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {formatRelative(update.created_at)}
                        </span>
                      </div>
                      <p className="text-muted-foreground">{update.message}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={closeDialog}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingIncident ? 'Post Update' : 'Create Incident'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
