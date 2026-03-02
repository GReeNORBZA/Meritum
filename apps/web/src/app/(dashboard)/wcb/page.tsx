'use client';

import * as React from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { useWcbClaims, type WcbClaim } from '@/hooks/api/use-wcb';
import { ROUTES } from '@/config/routes';
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
import { formatCurrency } from '@/lib/formatters/currency';
import { formatDate } from '@/lib/formatters/date';
import { useDebounce } from '@/hooks/use-debounce';
import { Plus, Search, X } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Constants ----------

const WCB_FORM_TYPES = [
  { value: '', label: 'All Form Types' },
  { value: 'C050E', label: 'C050E - Physician First Report' },
  { value: 'C050S', label: 'C050S - OIS First Report' },
  { value: 'C151', label: 'C151 - Progress Report' },
  { value: 'C151S', label: 'C151S - OIS Progress Report' },
  { value: 'C568', label: 'C568 - Medical Invoice' },
  { value: 'C568A', label: 'C568A - Consultation Report' },
  { value: 'C569', label: 'C569 - Supplies Invoice' },
  { value: 'C570', label: 'C570 - Invoice Correction' },
] as const;

const WCB_STATES = [
  { value: '', label: 'All Statuses' },
  { value: 'DRAFT', label: 'Draft' },
  { value: 'VALIDATED', label: 'Validated' },
  { value: 'QUEUED', label: 'Queued' },
  { value: 'SUBMITTED', label: 'Submitted' },
  { value: 'ACCEPTED', label: 'Accepted' },
  { value: 'PAID', label: 'Paid' },
  { value: 'REJECTED', label: 'Rejected' },
] as const;

// ---------- Columns ----------

const columns: ColumnDef<WcbClaim>[] = [
  {
    accessorKey: 'wcb_claim_number',
    header: 'WCB Claim #',
    cell: ({ row }) => (
      <Link
        href={ROUTES.WCB_DETAIL(row.original.id)}
        className="font-mono text-sm font-medium hover:underline"
      >
        {row.original.wcb_claim_number || row.original.id.slice(0, 8)}
      </Link>
    ),
  },
  {
    accessorKey: 'form_id',
    header: 'Form Type',
    cell: ({ row }) => (
      <Badge variant="outline" className="font-mono text-xs">
        {row.original.form_id}
      </Badge>
    ),
  },
  {
    id: 'patient',
    header: 'Patient / Claimant',
    cell: ({ row }) => (
      <span className="text-sm">
        {row.original.patient_name || row.original.patient_id}
      </span>
    ),
  },
  {
    accessorKey: 'state',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.state} />,
  },
  {
    accessorKey: 'created_at',
    header: 'Date Created',
    cell: ({ row }) => (
      <span className="text-sm">{formatDate(row.original.created_at)}</span>
    ),
  },
  {
    accessorKey: 'total_fee',
    header: 'Fee',
    cell: ({ row }) => (
      <span className="text-sm font-medium">
        {row.original.total_fee ? formatCurrency(row.original.total_fee) : '-'}
      </span>
    ),
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => (
      <div className="flex justify-end">
        <Link href={ROUTES.WCB_DETAIL(row.original.id)}>
          <Button variant="ghost" size="sm">
            View
          </Button>
        </Link>
      </div>
    ),
  },
];

// ---------- Main Page ----------

function WcbClaimsPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const initialPage = Number(searchParams.get('page')) || 1;
  const initialFormType = searchParams.get('form_id') || '';
  const initialState = searchParams.get('state') || '';
  const initialSearch = searchParams.get('search') || '';

  const [page, setPage] = React.useState(initialPage);
  const [pageSize, setPageSize] = React.useState(25);
  const [formTypeFilter, setFormTypeFilter] = React.useState(initialFormType);
  const [stateFilter, setStateFilter] = React.useState(initialState);
  const [searchInput, setSearchInput] = React.useState(initialSearch);

  const search = useDebounce(searchInput, 300);

  // Sync URL params
  React.useEffect(() => {
    const params = new URLSearchParams();
    if (page > 1) params.set('page', String(page));
    if (formTypeFilter) params.set('form_id', formTypeFilter);
    if (stateFilter) params.set('state', stateFilter);
    if (search) params.set('search', search);
    const qs = params.toString();
    router.replace(qs ? `${ROUTES.WCB}?${qs}` : ROUTES.WCB, { scroll: false });
  }, [page, formTypeFilter, stateFilter, search, router]);

  const { data, isLoading } = useWcbClaims({
    form_id: formTypeFilter || undefined,
    state: stateFilter || undefined,
    search: search || undefined,
    page,
    pageSize,
  });

  const hasActiveFilters = formTypeFilter || stateFilter || search;

  const clearFilters = () => {
    setFormTypeFilter('');
    setStateFilter('');
    setSearchInput('');
    setPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">WCB Claims</h1>
          <p className="text-muted-foreground">
            Manage Workers&apos; Compensation Board claims and reports
          </p>
        </div>
        <Link href={ROUTES.WCB_NEW}>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            New WCB Claim
          </Button>
        </Link>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by claim #, patient..."
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>

        <Select
          value={formTypeFilter}
          onValueChange={(val) => {
            setFormTypeFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[220px]">
            <SelectValue placeholder="All Form Types" />
          </SelectTrigger>
          <SelectContent>
            {WCB_FORM_TYPES.map((ft) => (
              <SelectItem key={ft.value} value={ft.value}>
                {ft.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={stateFilter}
          onValueChange={(val) => {
            setStateFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            {WCB_STATES.map((s) => (
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

export default function WcbClaimsPage() {
  return (
    <React.Suspense>
      <WcbClaimsPageContent />
    </React.Suspense>
  );
}
