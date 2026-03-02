'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { useAuthStore } from '@/stores/auth.store';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatDateTime, formatRelative } from '@/lib/formatters/date';
import { useDebounce } from '@/hooks/use-debounce';
import { Search, UserPlus, Filter, X } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface Ticket {
  id: string;
  ticket_number: string;
  subject: string;
  user_name: string;
  user_email: string;
  category: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  status: 'OPEN' | 'PENDING' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';
  assigned_to: string | null;
  assigned_name: string | null;
  created_at: string;
  updated_at: string;
}

interface TicketsResponse {
  data: Ticket[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

const PRIORITY_OPTIONS = [
  { value: '', label: 'All Priorities' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'urgent', label: 'Urgent' },
] as const;

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'OPEN', label: 'Open' },
  { value: 'PENDING', label: 'Pending' },
  { value: 'IN_PROGRESS', label: 'In Progress' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'CLOSED', label: 'Closed' },
] as const;

const priorityVariantMap: Record<string, 'secondary' | 'default' | 'warning' | 'destructive'> = {
  low: 'secondary',
  medium: 'default',
  high: 'warning',
  urgent: 'destructive',
};

// ---------- Main Page ----------

export default function AdminTicketsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [searchInput, setSearchInput] = React.useState('');
  const [priorityFilter, setPriorityFilter] = React.useState('');
  const [statusFilter, setStatusFilter] = React.useState('');

  const search = useDebounce(searchInput, 300);

  const filters = {
    search: search || undefined,
    priority: priorityFilter || undefined,
    status: statusFilter || undefined,
    page,
    pageSize,
  };

  const queryKey = ['admin', 'tickets', filters];

  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      api.get<TicketsResponse>('/api/v1/admin/tickets', { params: filters }),
  });

  const assignMutation = useMutation({
    mutationFn: (ticketId: string) =>
      api.patch(`/api/v1/admin/tickets/${ticketId}`, {
        assigned_to: user?.userId,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'tickets'] });
    },
  });

  const updatePriorityMutation = useMutation({
    mutationFn: ({ ticketId, priority }: { ticketId: string; priority: string }) =>
      api.patch(`/api/v1/admin/tickets/${ticketId}`, { priority }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'tickets'] });
    },
  });

  const hasActiveFilters = priorityFilter || statusFilter || search;

  const clearFilters = () => {
    setPriorityFilter('');
    setStatusFilter('');
    setSearchInput('');
    setPage(1);
  };

  // ---------- Columns ----------

  const columns: ColumnDef<Ticket>[] = [
    {
      accessorKey: 'ticket_number',
      header: 'Ticket #',
      cell: ({ row }) => (
        <span className="font-mono text-sm font-medium">
          {row.original.ticket_number}
        </span>
      ),
    },
    {
      accessorKey: 'subject',
      header: 'Subject',
      cell: ({ row }) => (
        <span className="text-sm line-clamp-1">{row.original.subject}</span>
      ),
    },
    {
      id: 'user',
      header: 'User',
      cell: ({ row }) => (
        <div className="text-sm">
          <p className="font-medium">{row.original.user_name}</p>
          <p className="text-xs text-muted-foreground">{row.original.user_email}</p>
        </div>
      ),
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: ({ row }) => (
        <Badge variant="outline" className="capitalize">
          {row.original.category.replace(/_/g, ' ')}
        </Badge>
      ),
    },
    {
      accessorKey: 'priority',
      header: 'Priority',
      cell: ({ row }) => (
        <Select
          value={row.original.priority}
          onValueChange={(val) =>
            updatePriorityMutation.mutate({
              ticketId: row.original.id,
              priority: val,
            })
          }
          disabled={updatePriorityMutation.isPending}
        >
          <SelectTrigger className="h-7 w-[100px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="urgent">Urgent</SelectItem>
          </SelectContent>
        </Select>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelative(row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="flex justify-end gap-1">
          {!row.original.assigned_to && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => assignMutation.mutate(row.original.id)}
              disabled={assignMutation.isPending}
            >
              <UserPlus className="mr-1 h-3 w-3" />
              Assign to Me
            </Button>
          )}
          {row.original.assigned_to && (
            <Badge variant="secondary" className="text-xs">
              {row.original.assigned_name ?? 'Assigned'}
            </Badge>
          )}
        </div>
      ),
    },
  ];

  // ---------- Stats ----------

  const tickets = data?.data ?? [];
  const openCount = tickets.filter(
    (t) => t.status === 'OPEN' || t.status === 'PENDING'
  ).length;
  const urgentCount = tickets.filter((t) => t.priority === 'urgent').length;
  const unassignedCount = tickets.filter((t) => !t.assigned_to).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Support Triage</h1>
        <p className="text-muted-foreground">
          Review and manage incoming support tickets
        </p>
      </div>

      {/* Quick Stats */}
      <div className="flex gap-4">
        <Badge variant="outline" className="px-3 py-1 text-sm">
          {data?.pagination?.total ?? 0} Total
        </Badge>
        <Badge variant="warning" className="px-3 py-1 text-sm">
          {openCount} Open
        </Badge>
        {urgentCount > 0 && (
          <Badge variant="destructive" className="px-3 py-1 text-sm">
            {urgentCount} Urgent
          </Badge>
        )}
        <Badge variant="secondary" className="px-3 py-1 text-sm">
          {unassignedCount} Unassigned
        </Badge>
      </div>

      {/* Search + Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search tickets..."
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
        <Select
          value={priorityFilter}
          onValueChange={(val) => {
            setPriorityFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="All Priorities" />
          </SelectTrigger>
          <SelectContent>
            {PRIORITY_OPTIONS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={statusFilter}
          onValueChange={(val) => {
            setStatusFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            <X className="mr-1 h-3 w-3" />
            Clear
          </Button>
        )}
      </div>

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={tickets}
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
    </div>
  );
}
