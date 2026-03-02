'use client';

import * as React from 'react';
import Link from 'next/link';
import { useBatches, type Batch } from '@/hooks/api/use-claims';
import { ROUTES } from '@/config/routes';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatCurrency } from '@/lib/formatters/currency';
import { formatDate } from '@/lib/formatters/date';
import { Package, Eye } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Constants ----------

const BATCH_STATES = [
  { value: '', label: 'All Statuses' },
  { value: 'DRAFT', label: 'Draft' },
  { value: 'PENDING', label: 'Pending' },
  { value: 'SUBMITTED', label: 'Submitted' },
  { value: 'ASSESSED', label: 'Assessed' },
  { value: 'COMPLETED', label: 'Completed' },
] as const;

// ---------- Columns ----------

const columns: ColumnDef<Batch>[] = [
  {
    accessorKey: 'batch_number',
    header: 'Batch #',
    cell: ({ row }) => (
      <Link
        href={ROUTES.BATCH_DETAIL(row.original.id)}
        className="font-mono text-sm font-medium hover:underline"
      >
        {row.original.batch_number}
      </Link>
    ),
  },
  {
    accessorKey: 'state',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.state} />,
  },
  {
    accessorKey: 'claims_count',
    header: 'Claims Count',
    cell: ({ row }) => (
      <span className="text-sm">{row.original.claims_count}</span>
    ),
  },
  {
    accessorKey: 'total_amount',
    header: 'Total Amount',
    cell: ({ row }) => (
      <span className="text-sm font-medium">
        {formatCurrency(row.original.total_amount)}
      </span>
    ),
  },
  {
    id: 'submission_date',
    header: 'Submission Date',
    cell: ({ row }) =>
      row.original.submission_date ? (
        <span className="text-sm">
          {formatDate(row.original.submission_date)}
        </span>
      ) : (
        <span className="text-sm text-muted-foreground">Not submitted</span>
      ),
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => (
      <div className="flex justify-end">
        <Link href={ROUTES.BATCH_DETAIL(row.original.id)}>
          <Button variant="ghost" size="sm">
            <Eye className="mr-1 h-4 w-4" />
            View
          </Button>
        </Link>
      </div>
    ),
  },
];

// ---------- Main Page ----------

export default function BatchesPage() {
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [stateFilter, setStateFilter] = React.useState('');

  const { data, isLoading } = useBatches({
    state: stateFilter || undefined,
    page,
    pageSize,
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Batches</h1>
          <p className="text-muted-foreground">
            Manage claim submission batches
          </p>
        </div>
        <Button variant="outline">
          <Package className="mr-2 h-4 w-4" />
          Review Current Batch
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <Select
          value={stateFilter}
          onValueChange={(val) => {
            setStateFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            {BATCH_STATES.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
