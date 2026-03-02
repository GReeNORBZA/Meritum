'use client';

import * as React from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { useTickets, type Ticket } from '@/hooks/api/use-support';
import { ROUTES } from '@/config/routes';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatDate, formatRelative } from '@/lib/formatters/date';
import { Plus } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Constants ----------

const TICKET_STATUSES = [
  { value: '', label: 'All Statuses' },
  { value: 'OPEN', label: 'Open' },
  { value: 'PENDING', label: 'Pending' },
  { value: 'IN_PROGRESS', label: 'In Progress' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'CLOSED', label: 'Closed' },
] as const;

const CATEGORY_LABELS: Record<string, string> = {
  billing: 'Billing',
  technical: 'Technical',
  claims: 'Claims',
  account: 'Account',
  other: 'Other',
};

// ---------- Columns ----------

const columns: ColumnDef<Ticket>[] = [
  {
    accessorKey: 'ticket_number',
    header: 'Ticket #',
    cell: ({ row }) => (
      <Link
        href={ROUTES.SUPPORT_TICKET_DETAIL(row.original.id)}
        className="font-mono text-sm font-medium hover:underline"
      >
        {row.original.ticket_number}
      </Link>
    ),
  },
  {
    accessorKey: 'subject',
    header: 'Subject',
    cell: ({ row }) => (
      <Link
        href={ROUTES.SUPPORT_TICKET_DETAIL(row.original.id)}
        className="text-sm hover:underline max-w-[300px] truncate block"
      >
        {row.original.subject}
      </Link>
    ),
  },
  {
    accessorKey: 'category',
    header: 'Category',
    cell: ({ row }) => (
      <Badge variant="outline" className="text-xs capitalize">
        {CATEGORY_LABELS[row.original.category] ?? row.original.category}
      </Badge>
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
        {formatDate(row.original.created_at)}
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
        <Link href={ROUTES.SUPPORT_TICKET_DETAIL(row.original.id)}>
          <Button variant="ghost" size="sm">
            View
          </Button>
        </Link>
      </div>
    ),
  },
];

// ---------- Main Page ----------

function TicketsPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const initialPage = Number(searchParams.get('page')) || 1;
  const initialStatus = searchParams.get('status') || '';

  const [page, setPage] = React.useState(initialPage);
  const [pageSize, setPageSize] = React.useState(20);
  const [statusFilter, setStatusFilter] = React.useState(initialStatus);

  // Sync URL params
  React.useEffect(() => {
    const params = new URLSearchParams();
    if (page > 1) params.set('page', String(page));
    if (statusFilter) params.set('status', statusFilter);
    const qs = params.toString();
    router.replace(qs ? `${ROUTES.SUPPORT_TICKETS}?${qs}` : ROUTES.SUPPORT_TICKETS, {
      scroll: false,
    });
  }, [page, statusFilter, router]);

  const { data, isLoading } = useTickets({
    status: statusFilter || undefined,
    page,
    pageSize,
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Support Tickets</h1>
          <p className="text-muted-foreground">
            Track and manage your support requests
          </p>
        </div>
        <Link href={ROUTES.SUPPORT_TICKET_NEW}>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            New Ticket
          </Button>
        </Link>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <Select
          value={statusFilter}
          onValueChange={(val) => {
            setStatusFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            {TICKET_STATUSES.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {statusFilter && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStatusFilter('');
              setPage(1);
            }}
          >
            Clear Filter
          </Button>
        )}
      </div>

      {/* Data Table */}
      <DataTable
        columns={columns}
        data={data?.data ?? []}
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

export default function TicketsPage() {
  return (
    <React.Suspense>
      <TicketsPageContent />
    </React.Suspense>
  );
}
