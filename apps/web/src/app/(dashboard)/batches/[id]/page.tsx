'use client';

import * as React from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useBatch, type Claim } from '@/hooks/api/use-claims';
import { ROUTES } from '@/config/routes';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { formatCurrency } from '@/lib/formatters/currency';
import { formatDate, formatDateTime } from '@/lib/formatters/date';
import {
  ArrowLeft,
  Package,
  FileText,
  DollarSign,
  Calendar,
  Hash,
} from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Claim Columns ----------

const claimColumns: ColumnDef<Claim>[] = [
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
    header: 'Billed',
    cell: ({ row }) => (
      <span className="text-sm">{formatCurrency(row.original.total_fee)}</span>
    ),
  },
  {
    id: 'assessed',
    header: 'Assessed',
    cell: ({ row }) =>
      row.original.total_assessed ? (
        <span className="text-sm">
          {formatCurrency(row.original.total_assessed)}
        </span>
      ) : (
        <span className="text-sm text-muted-foreground">--</span>
      ),
  },
];

// ---------- Loading Skeleton ----------

function BatchDetailSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-64" />
      <div className="grid gap-4 sm:grid-cols-4">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
      <Skeleton className="h-96 w-full" />
    </div>
  );
}

// ---------- Main Page ----------

export default function BatchDetailPage() {
  const params = useParams();
  const batchId = params.id as string;

  const { data, isLoading } = useBatch(batchId);
  const batch = data?.data;

  if (isLoading) {
    return <BatchDetailSkeleton />;
  }

  if (!batch) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg text-muted-foreground">Batch not found.</p>
        <Link href={ROUTES.BATCHES}>
          <Button variant="outline" className="mt-4">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Batches
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href={ROUTES.BATCHES}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight font-mono">
              {batch.batch_number}
            </h1>
            <StatusBadge status={batch.state} />
          </div>
          <p className="text-sm text-muted-foreground">
            Created {formatDate(batch.created_at)}
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Hash className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Claims</p>
              <p className="text-lg font-bold">{batch.claims_count}</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <DollarSign className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Total Billed</p>
              <p className="text-lg font-bold">
                {formatCurrency(batch.total_amount)}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <DollarSign className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Total Assessed</p>
              <p className="text-lg font-bold">
                {batch.total_assessed
                  ? formatCurrency(batch.total_assessed)
                  : '--'}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Calendar className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Submitted</p>
              <p className="text-lg font-bold">
                {batch.submission_date
                  ? formatDate(batch.submission_date)
                  : 'Pending'}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Status Tracking */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            Batch Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            {['DRAFT', 'SUBMITTED', 'ASSESSED', 'COMPLETED'].map(
              (step, index) => {
                const states = ['DRAFT', 'SUBMITTED', 'ASSESSED', 'COMPLETED'];
                const currentIndex = states.indexOf(batch.state);
                const isCompleted = index <= currentIndex;
                const isCurrent = index === currentIndex;

                return (
                  <React.Fragment key={step}>
                    <div className="flex flex-col items-center gap-1">
                      <div
                        className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-medium ${
                          isCompleted
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted text-muted-foreground'
                        } ${isCurrent ? 'ring-2 ring-primary ring-offset-2' : ''}`}
                      >
                        {index + 1}
                      </div>
                      <span
                        className={`text-xs ${
                          isCompleted
                            ? 'font-medium text-primary'
                            : 'text-muted-foreground'
                        }`}
                      >
                        {step.charAt(0) + step.slice(1).toLowerCase()}
                      </span>
                    </div>
                    {index < 3 && (
                      <div
                        className={`h-0.5 flex-1 ${
                          index < currentIndex ? 'bg-primary' : 'bg-muted'
                        }`}
                      />
                    )}
                  </React.Fragment>
                );
              }
            )}
          </div>
        </CardContent>
      </Card>

      {/* Assessment Results */}
      {batch.assessed_date && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Assessment Results
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-3">
              <div>
                <p className="text-xs text-muted-foreground">Assessed Date</p>
                <p className="text-sm font-medium">
                  {formatDateTime(batch.assessed_date)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Total Billed</p>
                <p className="text-sm font-medium">
                  {formatCurrency(batch.total_amount)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Total Assessed</p>
                <p className="text-sm font-medium">
                  {batch.total_assessed
                    ? formatCurrency(batch.total_assessed)
                    : '--'}
                </p>
              </div>
            </div>
            {batch.total_assessed && (
              <>
                <Separator />
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">
                    Variance:
                  </span>
                  <span
                    className={`text-sm font-medium ${
                      parseFloat(batch.total_assessed) >=
                      parseFloat(batch.total_amount)
                        ? 'text-green-600'
                        : 'text-destructive'
                    }`}
                  >
                    {formatCurrency(
                      String(
                        parseFloat(batch.total_assessed) -
                          parseFloat(batch.total_amount)
                      )
                    )}
                  </span>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Claims in Batch */}
      <Card>
        <CardHeader>
          <CardTitle>Claims in Batch</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={claimColumns}
            data={batch.claims ?? []}
            isLoading={false}
          />
        </CardContent>
      </Card>
    </div>
  );
}
