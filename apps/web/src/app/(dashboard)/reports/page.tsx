'use client';

import * as React from 'react';
import {
  useReports,
  useGenerateReport,
  type Report,
  type GenerateReportInput,
} from '@/hooks/api/use-analytics';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { ReportSubscriptions } from '@/components/domain/analytics/report-subscriptions';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { formatDate } from '@/lib/formatters/date';
import { Plus, Download, FileText, Loader2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Constants ----------

const REPORT_TYPES = [
  { value: 'revenue_summary', label: 'Revenue Summary' },
  { value: 'rejection_analysis', label: 'Rejection Analysis' },
  { value: 'aging_report', label: 'Aging Report' },
  { value: 'wcb_summary', label: 'WCB Summary' },
  { value: 'ai_coach_performance', label: 'AI Coach Performance' },
  { value: 'multi_site_comparison', label: 'Multi-Site Comparison' },
  { value: 'monthly_overview', label: 'Monthly Overview' },
  { value: 'annual_summary', label: 'Annual Summary' },
] as const;

const PERIOD_OPTIONS = [
  { value: 'this_week', label: 'This Week' },
  { value: 'this_month', label: 'This Month' },
  { value: 'this_quarter', label: 'This Quarter' },
  { value: 'this_year', label: 'This Year' },
] as const;

const FORMAT_OPTIONS = [
  { value: 'pdf', label: 'PDF' },
  { value: 'csv', label: 'CSV' },
  { value: 'xlsx', label: 'Excel (XLSX)' },
] as const;

// ---------- Columns ----------

const columns: ColumnDef<Report>[] = [
  {
    accessorKey: 'name',
    header: 'Report Name',
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <FileText className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">{row.original.name}</span>
      </div>
    ),
  },
  {
    accessorKey: 'report_type',
    header: 'Type',
    cell: ({ row }) => {
      const label =
        REPORT_TYPES.find((rt) => rt.value === row.original.report_type)?.label ??
        row.original.report_type;
      return (
        <Badge variant="outline" className="text-xs">
          {label}
        </Badge>
      );
    },
  },
  {
    accessorKey: 'created_at',
    header: 'Date',
    cell: ({ row }) => (
      <span className="text-sm">{formatDate(row.original.created_at)}</span>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => {
      if (row.original.status === 'COMPLETED' && row.original.download_url) {
        return (
          <div className="flex justify-end">
            <Button variant="ghost" size="sm" asChild>
              <a href={row.original.download_url} download>
                <Download className="mr-2 h-4 w-4" />
                Download
              </a>
            </Button>
          </div>
        );
      }

      if (row.original.status === 'GENERATING' || row.original.status === 'PENDING') {
        return (
          <div className="flex items-center justify-end gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Processing...
          </div>
        );
      }

      return null;
    },
  },
];

// ---------- Generate Report Dialog ----------

function GenerateReportDialog({ onClose }: { onClose: () => void }) {
  const generateMutation = useGenerateReport();
  const [reportType, setReportType] = React.useState('');
  const [period, setPeriod] = React.useState('this_month');
  const [format, setFormat] = React.useState<GenerateReportInput['format']>('pdf');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportType) return;

    generateMutation.mutate(
      {
        report_type: reportType,
        period,
        format,
      },
      {
        onSuccess: () => {
          onClose();
          setReportType('');
          setPeriod('this_month');
          setFormat('pdf');
        },
      }
    );
  };

  return (
    <DialogContent>
      <form onSubmit={handleSubmit}>
        <DialogHeader>
          <DialogTitle>Generate Report</DialogTitle>
          <DialogDescription>
            Select the report type, period, and format to generate a new report.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="gen-report-type">Report Type</Label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger id="gen-report-type">
                <SelectValue placeholder="Select report type..." />
              </SelectTrigger>
              <SelectContent>
                {REPORT_TYPES.map((rt) => (
                  <SelectItem key={rt.value} value={rt.value}>
                    {rt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="gen-period">Period</Label>
            <Select value={period} onValueChange={setPeriod}>
              <SelectTrigger id="gen-period">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PERIOD_OPTIONS.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="gen-format">Format</Label>
            <Select
              value={format}
              onValueChange={(val) =>
                setFormat(val as GenerateReportInput['format'])
              }
            >
              <SelectTrigger id="gen-format">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FORMAT_OPTIONS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!reportType || generateMutation.isPending}>
            {generateMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              'Generate Report'
            )}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

// ---------- Main Page ----------

export default function ReportsPage() {
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [generateDialogOpen, setGenerateDialogOpen] = React.useState(false);

  const { data, isLoading } = useReports({ page, pageSize });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-muted-foreground">
            Generate, download, and manage billing reports
          </p>
        </div>
        <Dialog open={generateDialogOpen} onOpenChange={setGenerateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Generate Report
            </Button>
          </DialogTrigger>
          <GenerateReportDialog onClose={() => setGenerateDialogOpen(false)} />
        </Dialog>
      </div>

      {/* Reports Table */}
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

      {/* Report Subscriptions */}
      <ReportSubscriptions />
    </div>
  );
}
