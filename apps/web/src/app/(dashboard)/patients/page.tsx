'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePatients, useRecentPatients, type Patient } from '@/hooks/api/use-patients';
import { ROUTES } from '@/config/routes';
import { DataTable } from '@/components/data-table/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Plus, Search, UserRound } from 'lucide-react';
import { maskPhn, formatPhn } from '@/lib/formatters/phn';
import { formatDate, formatRelative } from '@/lib/formatters/date';
import { useDebounce } from '@/hooks/use-debounce';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Columns ----------

const columns: ColumnDef<Patient>[] = [
  {
    accessorKey: 'phn',
    header: 'PHN',
    cell: ({ row }) => (
      <span className="font-mono text-sm">
        {row.original.phn ? maskPhn(formatPhn(row.original.phn)) : '---'}
      </span>
    ),
  },
  {
    id: 'name',
    header: 'Name',
    cell: ({ row }) => (
      <Link
        href={ROUTES.PATIENT_DETAIL(row.original.id)}
        className="font-medium hover:underline"
      >
        {row.original.last_name}, {row.original.first_name}
        {row.original.middle_name ? ` ${row.original.middle_name.charAt(0)}.` : ''}
      </Link>
    ),
  },
  {
    accessorKey: 'date_of_birth',
    header: 'Date of Birth',
    cell: ({ row }) => formatDate(row.original.date_of_birth),
  },
  {
    accessorKey: 'province',
    header: 'Province',
    cell: ({ row }) => (
      <Badge variant="outline">{row.original.phn_province || row.original.province || 'AB'}</Badge>
    ),
  },
  {
    accessorKey: 'last_visit_date',
    header: 'Last Visit',
    cell: ({ row }) =>
      row.original.last_visit_date
        ? formatRelative(row.original.last_visit_date)
        : <span className="text-muted-foreground">No visits</span>,
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => (
      <div className="flex justify-end gap-1">
        <Link href={ROUTES.PATIENT_DETAIL(row.original.id)}>
          <Button variant="ghost" size="sm">View</Button>
        </Link>
        <Link href={ROUTES.PATIENT_EDIT(row.original.id)}>
          <Button variant="ghost" size="sm">Edit</Button>
        </Link>
      </div>
    ),
  },
];

// ---------- Recent Patients ----------

function RecentPatientsSection() {
  const { data, isLoading } = useRecentPatients(5);
  const patients = data?.data ?? [];

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Patients</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3 overflow-x-auto pb-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-48 shrink-0 rounded-md" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (patients.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent Patients</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-3 overflow-x-auto pb-2">
          {patients.map((patient) => (
            <Link
              key={patient.id}
              href={ROUTES.PATIENT_DETAIL(patient.id)}
              className="flex shrink-0 items-center gap-3 rounded-lg border p-3 transition-colors hover:bg-accent"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                <UserRound className="h-4 w-4 text-primary" />
              </div>
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">
                  {patient.last_name}, {patient.first_name}
                </p>
                <p className="text-xs text-muted-foreground">
                  {patient.phn ? maskPhn(formatPhn(patient.phn)) : 'No PHN'}
                </p>
              </div>
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Main Page ----------

export default function PatientsPage() {
  const [searchInput, setSearchInput] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const search = useDebounce(searchInput, 300);

  const { data, isLoading } = usePatients({ search, page, pageSize });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Patients</h1>
          <p className="text-muted-foreground">
            Manage your patient registry
          </p>
        </div>
        <div className="flex gap-2">
          <Link href={ROUTES.PATIENTS_IMPORT}>
            <Button variant="outline">Import CSV</Button>
          </Link>
          <Link href={ROUTES.PATIENTS_NEW}>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Patient
            </Button>
          </Link>
        </div>
      </div>

      {/* Recent Patients */}
      <RecentPatientsSection />

      {/* Search + Filters */}
      <div className="flex gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by PHN, name, or DOB..."
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
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
