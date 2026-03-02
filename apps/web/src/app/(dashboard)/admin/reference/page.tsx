'use client';

import * as React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { DataTable } from '@/components/data-table/data-table';
import { StatusBadge } from '@/components/shared/status-badge';
import { FileUpload } from '@/components/forms/file-upload';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { formatDateTime, formatRelative } from '@/lib/formatters/date';
import {
  Upload,
  Rocket,
  History,
  FileSpreadsheet,
  CheckCircle,
  Loader2,
} from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';

// ---------- Types ----------

interface ReferenceUpload {
  id: string;
  filename: string;
  type: 'hsc' | 'diagnostic' | 'modifier' | 'functional_centre';
  status: 'pending' | 'staged' | 'published' | 'failed';
  record_count: number;
  added: number;
  updated: number;
  removed: number;
  uploaded_by: string;
  uploaded_at: string;
  published_at: string | null;
  version: number;
}

interface ReferenceItem {
  id: string;
  code: string;
  description: string;
  type: string;
  effective_date: string;
  end_date: string | null;
  status: 'ACTIVE' | 'INACTIVE';
}

interface UploadsResponse {
  data: ReferenceUpload[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

interface ReferenceItemsResponse {
  data: ReferenceItem[];
  pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
}

// ---------- Columns ----------

const uploadColumns: ColumnDef<ReferenceUpload>[] = [
  {
    accessorKey: 'filename',
    header: 'File',
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">{row.original.filename}</span>
      </div>
    ),
  },
  {
    accessorKey: 'type',
    header: 'Type',
    cell: ({ row }) => (
      <Badge variant="outline" className="capitalize">
        {row.original.type.replace(/_/g, ' ')}
      </Badge>
    ),
  },
  {
    accessorKey: 'record_count',
    header: 'Records',
    cell: ({ row }) => (
      <span className="text-sm">{row.original.record_count.toLocaleString()}</span>
    ),
  },
  {
    id: 'changes',
    header: 'Changes',
    cell: ({ row }) => (
      <div className="flex gap-2 text-xs">
        <span className="text-green-600">+{row.original.added}</span>
        <span className="text-blue-600">~{row.original.updated}</span>
        <span className="text-red-600">-{row.original.removed}</span>
      </div>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.status.toUpperCase()} />,
  },
  {
    accessorKey: 'version',
    header: 'Version',
    cell: ({ row }) => (
      <Badge variant="secondary">v{row.original.version}</Badge>
    ),
  },
  {
    accessorKey: 'uploaded_at',
    header: 'Uploaded',
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {formatRelative(row.original.uploaded_at)}
      </span>
    ),
  },
];

const referenceItemColumns: ColumnDef<ReferenceItem>[] = [
  {
    accessorKey: 'code',
    header: 'Code',
    cell: ({ row }) => (
      <span className="font-mono text-sm font-medium">{row.original.code}</span>
    ),
  },
  {
    accessorKey: 'description',
    header: 'Description',
    cell: ({ row }) => (
      <span className="text-sm">{row.original.description}</span>
    ),
  },
  {
    accessorKey: 'type',
    header: 'Type',
    cell: ({ row }) => (
      <Badge variant="outline" className="capitalize">
        {row.original.type.replace(/_/g, ' ')}
      </Badge>
    ),
  },
  {
    accessorKey: 'effective_date',
    header: 'Effective',
    cell: ({ row }) => (
      <span className="text-sm">{formatDateTime(row.original.effective_date)}</span>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
];

// ---------- Main Page ----------

export default function AdminReferencePage() {
  const queryClient = useQueryClient();

  const [uploadPage, setUploadPage] = React.useState(1);
  const [uploadPageSize, setUploadPageSize] = React.useState(10);
  const [itemsPage, setItemsPage] = React.useState(1);
  const [itemsPageSize, setItemsPageSize] = React.useState(20);
  const [isUploading, setIsUploading] = React.useState(false);

  const { data: uploadsData, isLoading: uploadsLoading } = useQuery({
    queryKey: [...queryKeys.reference.all, 'admin-uploads', { page: uploadPage, pageSize: uploadPageSize }],
    queryFn: () =>
      api.get<UploadsResponse>('/api/v1/admin/reference/uploads', {
        params: { page: uploadPage, pageSize: uploadPageSize },
      }),
  });

  const { data: itemsData, isLoading: itemsLoading } = useQuery({
    queryKey: [...queryKeys.reference.all, 'admin-items', { page: itemsPage, pageSize: itemsPageSize }],
    queryFn: () =>
      api.get<ReferenceItemsResponse>('/api/v1/admin/reference/items', {
        params: { page: itemsPage, pageSize: itemsPageSize },
      }),
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData();
      formData.append('file', file);
      return api.post('/api/v1/admin/reference/upload', formData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.all });
      setIsUploading(false);
    },
    onError: () => {
      setIsUploading(false);
    },
  });

  const publishMutation = useMutation({
    mutationFn: (uploadId: string) =>
      api.post(`/api/v1/admin/reference/publish/${uploadId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reference.all });
    },
  });

  const handleFileUpload = (files: File[]) => {
    if (files.length > 0) {
      setIsUploading(true);
      uploadMutation.mutate(files[0]);
    }
  };

  const stagedUploads = uploadsData?.data?.filter((u) => u.status === 'staged') ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Reference Data</h1>
        <p className="text-muted-foreground">
          Manage HSC codes, diagnostic codes, and other reference data
        </p>
      </div>

      <Tabs defaultValue="uploads" className="space-y-4">
        <TabsList>
          <TabsTrigger value="uploads">
            <Upload className="mr-2 h-4 w-4" />
            Uploads
          </TabsTrigger>
          <TabsTrigger value="staging">
            <Rocket className="mr-2 h-4 w-4" />
            Staging
            {stagedUploads.length > 0 && (
              <Badge variant="secondary" className="ml-2">
                {stagedUploads.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="data">
            <FileSpreadsheet className="mr-2 h-4 w-4" />
            Reference Items
          </TabsTrigger>
          <TabsTrigger value="history">
            <History className="mr-2 h-4 w-4" />
            Version History
          </TabsTrigger>
        </TabsList>

        {/* Upload Tab */}
        <TabsContent value="uploads" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Upload Reference Data</CardTitle>
              <CardDescription>
                Upload a CSV file containing HSC codes, diagnostic codes, or other reference data.
                Files are staged for review before publishing.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FileUpload
                accept=".csv,.xlsx"
                maxSize={50 * 1024 * 1024}
                onUpload={handleFileUpload}
                disabled={isUploading || uploadMutation.isPending}
              />
              {uploadMutation.isPending && (
                <div className="mt-4 flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Processing upload...
                </div>
              )}
              {uploadMutation.isSuccess && (
                <div className="mt-4 flex items-center gap-2 text-sm text-green-600">
                  <CheckCircle className="h-4 w-4" />
                  Upload processed successfully. Review in the Staging tab.
                </div>
              )}
            </CardContent>
          </Card>

          <DataTable
            columns={uploadColumns}
            data={uploadsData?.data ?? []}
            isLoading={uploadsLoading}
            pagination={{
              page: uploadPage,
              pageSize: uploadPageSize,
              total: uploadsData?.pagination?.total ?? 0,
            }}
            onPaginationChange={(newPage, newPageSize) => {
              setUploadPage(newPage);
              setUploadPageSize(newPageSize);
            }}
          />
        </TabsContent>

        {/* Staging Tab */}
        <TabsContent value="staging" className="space-y-4">
          {stagedUploads.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No staged uploads ready for publishing.
              </CardContent>
            </Card>
          ) : (
            stagedUploads.map((upload) => (
              <Card key={upload.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base">{upload.filename}</CardTitle>
                      <CardDescription>
                        {upload.record_count.toLocaleString()} records &middot;{' '}
                        <span className="text-green-600">+{upload.added} added</span>,{' '}
                        <span className="text-blue-600">~{upload.updated} updated</span>,{' '}
                        <span className="text-red-600">-{upload.removed} removed</span>
                      </CardDescription>
                    </div>
                    <Button
                      onClick={() => publishMutation.mutate(upload.id)}
                      disabled={publishMutation.isPending}
                    >
                      {publishMutation.isPending ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Rocket className="mr-2 h-4 w-4" />
                      )}
                      Publish
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">Type</p>
                      <p className="font-medium capitalize">{upload.type.replace(/_/g, ' ')}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Version</p>
                      <p className="font-medium">v{upload.version}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Uploaded By</p>
                      <p className="font-medium">{upload.uploaded_by}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Uploaded</p>
                      <p className="font-medium">{formatRelative(upload.uploaded_at)}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Reference Items Tab */}
        <TabsContent value="data" className="space-y-4">
          <DataTable
            columns={referenceItemColumns}
            data={itemsData?.data ?? []}
            isLoading={itemsLoading}
            pagination={{
              page: itemsPage,
              pageSize: itemsPageSize,
              total: itemsData?.pagination?.total ?? 0,
            }}
            onPaginationChange={(newPage, newPageSize) => {
              setItemsPage(newPage);
              setItemsPageSize(newPageSize);
            }}
          />
        </TabsContent>

        {/* Version History Tab */}
        <TabsContent value="history" className="space-y-4">
          <DataTable
            columns={[
              ...uploadColumns.filter((c) => 'accessorKey' in c && c.accessorKey !== 'status'),
              {
                accessorKey: 'published_at',
                header: 'Published',
                cell: ({ row }) => (
                  <span className="text-sm text-muted-foreground">
                    {row.original.published_at
                      ? formatDateTime(row.original.published_at)
                      : '--'}
                  </span>
                ),
              },
            ]}
            data={
              uploadsData?.data?.filter((u) => u.status === 'published') ?? []
            }
            isLoading={uploadsLoading}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
