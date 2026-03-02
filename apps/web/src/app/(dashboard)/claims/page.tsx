'use client';

import * as React from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { useClaims, type Claim } from '@/hooks/api/use-claims';
import { ROUTES } from '@/config/routes';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { DatePicker } from '@/components/forms/date-picker';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { formatCurrency } from '@/lib/formatters/currency';
import { formatDate, formatDateISO } from '@/lib/formatters/date';
import { useDebounce } from '@/hooks/use-debounce';
import { Plus, Search, Filter, X } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Constants ----------

const CLAIM_STATES = [
  { value: '', label: 'All States' },
  { value: 'DRAFT', label: 'Draft' },
  { value: 'VALIDATED', label: 'Validated' },
  { value: 'QUEUED', label: 'Queued' },
  { value: 'SUBMITTED', label: 'Submitted' },
  { value: 'ASSESSED', label: 'Assessed' },
  { value: 'PAID', label: 'Paid' },
  { value: 'REJECTED', label: 'Rejected' },
  { value: 'WRITTEN_OFF', label: 'Written Off' },
] as const;

// ---------- Columns ----------

const columns: ColumnDef<Claim>[] = [
  {
    accessorKey: 'claim_number',
    header: 'Claim #',
    cell: ({ row }) => (
      <Link
        href={ROUTES.CLAIM_DETAIL(row.original.id)}
        className="font-mono text-sm font-medium hover:underline"
      >
        {row.original.claim_number}
      </Link>
    ),
  },
  {
    id: 'patient',
    header: 'Patient',
    cell: ({ row }) => (
      <span className="text-sm">
        {row.original.patient_name || row.original.patient_id}
      </span>
    ),
  },
  {
    accessorKey: 'date_of_service',
    header: 'Service Date',
    cell: ({ row }) => (
      <span className="text-sm">{formatDate(row.original.date_of_service)}</span>
    ),
  },
  {
    id: 'hsc_codes',
    header: 'HSC Code(s)',
    cell: ({ row }) => (
      <div className="flex flex-wrap gap-1">
        {row.original.line_items.map((item) => (
          <Badge key={item.health_service_code} variant="outline" className="font-mono text-xs">
            {item.health_service_code}
          </Badge>
        ))}
      </div>
    ),
  },
  {
    accessorKey: 'state',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.state} />,
  },
  {
    accessorKey: 'total_fee',
    header: 'Amount',
    cell: ({ row }) => (
      <span className="text-sm font-medium">
        {formatCurrency(row.original.total_fee)}
      </span>
    ),
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => (
      <div className="flex justify-end">
        <Link href={ROUTES.CLAIM_DETAIL(row.original.id)}>
          <Button variant="ghost" size="sm">
            View
          </Button>
        </Link>
      </div>
    ),
  },
];

// ---------- Main Page ----------

function ClaimsPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // URL-synced state
  const initialPage = Number(searchParams.get('page')) || 1;
  const initialState = searchParams.get('state') || '';
  const initialSearch = searchParams.get('search') || '';

  const [page, setPage] = React.useState(initialPage);
  const [pageSize, setPageSize] = React.useState(25);
  const [stateFilter, setStateFilter] = React.useState(initialState);
  const [searchInput, setSearchInput] = React.useState(initialSearch);
  const [dateFrom, setDateFrom] = React.useState<Date | undefined>(undefined);
  const [dateTo, setDateTo] = React.useState<Date | undefined>(undefined);
  const [showFilters, setShowFilters] = React.useState(false);

  const search = useDebounce(searchInput, 300);

  // Sync URL params
  React.useEffect(() => {
    const params = new URLSearchParams();
    if (page > 1) params.set('page', String(page));
    if (stateFilter) params.set('state', stateFilter);
    if (search) params.set('search', search);
    const qs = params.toString();
    router.replace(qs ? `${ROUTES.CLAIMS}?${qs}` : ROUTES.CLAIMS, {
      scroll: false,
    });
  }, [page, stateFilter, search, router]);

  const { data, isLoading } = useClaims({
    state: stateFilter || undefined,
    date_from: dateFrom ? formatDateISO(dateFrom) : undefined,
    date_to: dateTo ? formatDateISO(dateTo) : undefined,
    search: search || undefined,
    page,
    pageSize,
  });

  const hasActiveFilters = stateFilter || dateFrom || dateTo || search;

  const clearFilters = () => {
    setStateFilter('');
    setSearchInput('');
    setDateFrom(undefined);
    setDateTo(undefined);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Claims</h1>
          <p className="text-muted-foreground">
            Manage AHCIP claims and track submissions
          </p>
        </div>
        <Link href={ROUTES.CLAIMS_NEW}>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            New Claim
          </Button>
        </Link>
      </div>

      {/* Search + Filter Toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by patient, claim #..."
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>

        <Select
          value={stateFilter}
          onValueChange={(val) => {
            setStateFilter(val);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="All States" />
          </SelectTrigger>
          <SelectContent>
            {CLAIM_STATES.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowFilters(!showFilters)}
        >
          <Filter className="mr-2 h-4 w-4" />
          {showFilters ? 'Hide Filters' : 'More Filters'}
        </Button>

        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            <X className="mr-1 h-3 w-3" />
            Clear
          </Button>
        )}
      </div>

      {/* Expanded Filters */}
      {showFilters && (
        <div className="grid grid-cols-1 gap-4 rounded-lg border p-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Date From</Label>
            <DatePicker
              value={dateFrom}
              onChange={(d) => {
                setDateFrom(d);
                setPage(1);
              }}
              placeholder="Start date..."
            />
          </div>
          <div className="space-y-2">
            <Label>Date To</Label>
            <DatePicker
              value={dateTo}
              onChange={(d) => {
                setDateTo(d);
                setPage(1);
              }}
              placeholder="End date..."
            />
          </div>
        </div>
      )}

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

export default function ClaimsPage() {
  return (
    <React.Suspense>
      <ClaimsPageContent />
    </React.Suspense>
  );
}
