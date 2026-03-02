'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { DataTable } from '@/components/data-table/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { formatDate } from '@/lib/formatters/date';
import { Plus, Pencil, Trash2, Calendar, Loader2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface Holiday {
  id: string;
  name: string;
  date: string;
  province: string;
  recurring: boolean;
  created_at: string;
  updated_at: string;
}

interface HolidaysResponse {
  data: Holiday[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

interface HolidayFormData {
  name: string;
  date: string;
  province: string;
  recurring: boolean;
}

const PROVINCES = [
  { value: 'AB', label: 'Alberta' },
  { value: 'BC', label: 'British Columbia' },
  { value: 'MB', label: 'Manitoba' },
  { value: 'NB', label: 'New Brunswick' },
  { value: 'NL', label: 'Newfoundland and Labrador' },
  { value: 'NS', label: 'Nova Scotia' },
  { value: 'NT', label: 'Northwest Territories' },
  { value: 'NU', label: 'Nunavut' },
  { value: 'ON', label: 'Ontario' },
  { value: 'PE', label: 'Prince Edward Island' },
  { value: 'QC', label: 'Quebec' },
  { value: 'SK', label: 'Saskatchewan' },
  { value: 'YT', label: 'Yukon' },
  { value: 'ALL', label: 'All Provinces (Federal)' },
] as const;

const EMPTY_FORM: HolidayFormData = {
  name: '',
  date: '',
  province: 'AB',
  recurring: false,
};

// ---------- Main Page ----------

export default function AdminHolidaysPage() {
  const queryClient = useQueryClient();

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editingHoliday, setEditingHoliday] = React.useState<Holiday | null>(null);
  const [formData, setFormData] = React.useState<HolidayFormData>(EMPTY_FORM);

  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.reference.holidays(), 'admin', { page, pageSize }],
    queryFn: () =>
      api.get<HolidaysResponse>('/api/v1/admin/holidays', {
        params: { page, pageSize },
      }),
  });

  const createMutation = useMutation({
    mutationFn: (payload: HolidayFormData) =>
      api.post('/api/v1/admin/holidays', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.holidays() });
      closeDialog();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...payload }: HolidayFormData & { id: string }) =>
      api.put(`/api/v1/admin/holidays/${id}`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.holidays() });
      closeDialog();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/holidays/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.holidays() });
    },
  });

  const openCreate = () => {
    setEditingHoliday(null);
    setFormData(EMPTY_FORM);
    setDialogOpen(true);
  };

  const openEdit = (holiday: Holiday) => {
    setEditingHoliday(holiday);
    setFormData({
      name: holiday.name,
      date: holiday.date,
      province: holiday.province,
      recurring: holiday.recurring,
    });
    setDialogOpen(true);
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setEditingHoliday(null);
    setFormData(EMPTY_FORM);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingHoliday) {
      updateMutation.mutate({ id: editingHoliday.id, ...formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const isSaving = createMutation.isPending || updateMutation.isPending;

  // ---------- Calendar View Data ----------

  const holidays = data?.data ?? [];
  const months = React.useMemo(() => {
    const monthMap = new Map<string, Holiday[]>();
    holidays.forEach((h) => {
      const monthKey = h.date.substring(0, 7); // yyyy-MM
      const existing = monthMap.get(monthKey) ?? [];
      existing.push(h);
      monthMap.set(monthKey, existing);
    });
    return Array.from(monthMap.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [holidays]);

  // ---------- Columns ----------

  const columns: ColumnDef<Holiday>[] = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: ({ row }) => (
        <span className="text-sm font-medium">{row.original.name}</span>
      ),
    },
    {
      accessorKey: 'date',
      header: 'Date',
      cell: ({ row }) => (
        <span className="text-sm">{formatDate(row.original.date)}</span>
      ),
    },
    {
      accessorKey: 'province',
      header: 'Province',
      cell: ({ row }) => (
        <Badge variant="outline">{row.original.province}</Badge>
      ),
    },
    {
      accessorKey: 'recurring',
      header: 'Recurring',
      cell: ({ row }) => (
        <Badge variant={row.original.recurring ? 'success' : 'secondary'}>
          {row.original.recurring ? 'Yes' : 'No'}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => openEdit(row.original)}
          >
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (window.confirm(`Delete holiday "${row.original.name}"?`)) {
                deleteMutation.mutate(row.original.id);
              }
            }}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Holiday Calendar</h1>
          <p className="text-muted-foreground">
            Manage statutory holidays for billing calculations
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          Add Holiday
        </Button>
      </div>

      {/* Calendar Overview */}
      {months.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {months.map(([monthKey, monthHolidays]) => (
            <Card key={monthKey}>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">
                  <Calendar className="mr-2 inline h-4 w-4" />
                  {formatDate(`${monthKey}-01`, 'MMMM yyyy')}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {monthHolidays.map((h) => (
                  <div
                    key={h.id}
                    className="flex items-center justify-between text-sm"
                  >
                    <span>{h.name}</span>
                    <span className="text-muted-foreground">
                      {formatDate(h.date, 'MMM d')}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={holidays}
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

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingHoliday ? 'Edit Holiday' : 'Add Holiday'}
            </DialogTitle>
            <DialogDescription>
              {editingHoliday
                ? 'Update the holiday details below.'
                : 'Add a new statutory holiday to the calendar.'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="holiday-name">Name</Label>
              <Input
                id="holiday-name"
                value={formData.name}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, name: e.target.value }))
                }
                placeholder="e.g. Canada Day"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="holiday-date">Date</Label>
              <Input
                id="holiday-date"
                type="date"
                value={formData.date}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, date: e.target.value }))
                }
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="holiday-province">Province</Label>
              <Select
                value={formData.province}
                onValueChange={(val) =>
                  setFormData((prev) => ({ ...prev, province: val }))
                }
              >
                <SelectTrigger id="holiday-province">
                  <SelectValue placeholder="Select province" />
                </SelectTrigger>
                <SelectContent>
                  {PROVINCES.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="holiday-recurring"
                checked={formData.recurring}
                onCheckedChange={(checked) =>
                  setFormData((prev) => ({ ...prev, recurring: checked }))
                }
              />
              <Label htmlFor="holiday-recurring">Recurring annually</Label>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={closeDialog}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {editingHoliday ? 'Save Changes' : 'Add Holiday'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
